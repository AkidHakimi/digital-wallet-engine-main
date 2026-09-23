'use strict';

var undici = require('undici');
var undiciPkg = require('undici/package.json');
var node_process = require('node:process');

/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */

/*
Background: node ships its own copy of undici in the platform but does not
expose it (there is no `node:undici`), so this package installs its own. A
dispatcher only works with the undici that created it -- the handler contract
changed across majors, so handing an installed v6 dispatcher to a platform v7
or v8 `fetch` fails with "invalid onError method". Which major the platform
provides varies by release line (node 22 has 6, node 24 has 7, node 26 has 8),
so no single installed version matches every supported runtime -- with undici 6
installed, both node 24 and node 26 take the fallback path below. See
digitalbazaar/http-client#43.
*/

// as long as an agent has a reference to it, its associated dispatcher will
// be kept in this cache for reuse
const DISPATCHER_CACHE = new WeakMap();

// on the fallback path, the `fetch` override built for a dispatcher is kept
// here for reuse; the dispatcher is held by DISPATCHER_CACHE for as long as
// its agent lives, so the override has the same lifetime as the agent
const FETCH_CACHE = new WeakMap();

// can only convert agent to dispatcher option on node 18.2+
const [major, minor] = node_process.versions.node.split('.').map(v => parseInt(v, 10));
const canConvert = (major > 18) || (major === 18 && minor >= 2);

/*
True when the installed and platform undici majors match, meaning their
dispatchers are interchangeable. Both reads are guarded: a future undici could
hide `package.json` behind an `exports` map, and `versions.undici` may be
absent. Either way fall back to `false` and use the installed undici's own
fetch -- the always-safe path -- rather than throwing at module load and
breaking `import` for every consumer.
*/
const platformFetchCompatible = (() => {
  try {
    const installedMajor = parseInt(undiciPkg.version, 10);
    const platformMajor = parseInt(node_process.versions.undici, 10);
    return platformMajor === installedMajor;
  } catch{
    return false;
  }
})();

// converts `agent`/`httpsAgent` option to a dispatcher option
function convertAgent(options) {
  if(!canConvert) {
    return options;
  }

  // do not override custom fetch function from another lib
  if(options?.fetch && !options.fetch._httpClientCustomFetch) {
    return options;
  }

  // only override if an agent option is present
  const agent = options?.agent || options?.httpsAgent;
  if(!agent) {
    return options;
  }

  // reuse the dispatcher built for this agent
  let dispatcher = DISPATCHER_CACHE.get(agent);
  if(!dispatcher) {
    dispatcher = new undici.Agent({connect: agent.options});
    DISPATCHER_CACHE.set(agent, dispatcher);
  }

  // drop the converted legacy options so they are not forwarded to `fetch`
  const rest = {...options};
  delete rest.agent;
  delete rest.httpsAgent;

  // majors match: hand the dispatcher to `ky`, which forwards it to the
  // platform `fetch` (`ky` deliberately keeps `dispatcher` out of its
  // request-option registry so it reaches fetch) -- no wrapper needed
  if(platformFetchCompatible) {
    return {...rest, dispatcher};
  }

  // incompatible platform `fetch` that rejects this dispatcher, so route
  // through the installed undici's own fetch via an override
  let fetch = FETCH_CACHE.get(dispatcher);
  if(!fetch) {
    fetch = createFetch(dispatcher);
    fetch._httpClientCustomFetch = true;
    FETCH_CACHE.set(dispatcher, fetch);
  }
  return {...rest, fetch};
}

/*
Create fetch override uses custom `dispatcher`; when incompatible, the platform
`Request` that `ky` creates cannot be consumed by the installed undici's fetch
directly, so it is rebuilt as the installed undici's own `Request` here.

Passing the platform `Request` as undici's `Request` *init* (its second
constructor argument) works because undici's own `Request` constructor performs
its own `RequestInit` dictionary conversion -- it reads exactly the fields its
own implementation understands directly off the object it's given, duck-typed
rather than `instanceof`-checked, so it stays correct automatically as undici's
own supported fields evolve. No manual allow/deny-list of `RequestInit` fields
is needed or maintained here.
*/
function createFetch(defaultDispatcher) {
  return function fetch(input, init) {
    const dispatcher = init?.dispatcher || defaultDispatcher;
    if(input && typeof input === 'object' && typeof input.url === 'string') {
      input = new undici.Request(input.url, input);
    }
    return undici.fetch(input, {...init, dispatcher});
  };
}

function deferred(f) {
  let promise;

  return {
    then(
      onfulfilled,
      onrejected
    ) {
      // Use logical OR assignment when Node.js 14.x support is dropped
      //promise ||= new Promise(resolve => resolve(f()));
      promise || (promise = new Promise(resolve => resolve(f())));
      return promise.then(
        onfulfilled,
        onrejected
      );
    }
  };
}

/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc.
 */

const kyOriginalPromise = deferred(() => import('ky')
  .then(({default: ky}) => ky));

const DEFAULT_HEADERS = {
  Accept: 'application/ld+json, application/json'
};

// methods to proxy from ky
const PROXY_METHODS = new Set([
  'get', 'post', 'put', 'push', 'patch', 'head', 'delete'
]);

/**
 * Returns a custom httpClient instance. Used to specify default headers and
 * other default overrides.
 *
 * @param {object} [options={}] - Options hashmap.
 * @param {object} [options.parent] - The ky promise to inherit from.
 * @param {object} [options.headers={}] - Default header overrides.
 * @param {object} [options.params] - Other default overrides.
 *
 * @returns {Function} Custom httpClient instance.
 */
function createInstance({
  parent = kyOriginalPromise, headers = {}, ...params
} = {}) {
  // convert legacy agent options
  params = convertAgent(params);

  // create new ky instance that will asynchronously resolve
  const kyPromise = deferred(() => parent.then(kyBase => {
    let ky;
    if(parent === kyOriginalPromise) {
      // ensure default headers, allow overrides
      ky = kyBase.create({
        headers: {...DEFAULT_HEADERS, ...headers},
        ...params
      });
    } else {
      // extend parent
      ky = kyBase.extend({headers, ...params});
    }
    return ky;
  }));

  return _createHttpClient(kyPromise);
}

function _createHttpClient(kyPromise) {
  async function httpClient(...args) {
    const ky = await kyPromise;
    const method = ((args[1] && args[1].method) || 'get').toLowerCase();
    if(PROXY_METHODS.has(method)) {
      return httpClient[method].apply(ky[method], args);
    }

    // convert legacy agent options
    args[1] = convertAgent(args[1]);
    return ky.apply(ky, args);
  }

  for(const method of PROXY_METHODS) {
    httpClient[method] = async function(...args) {
      const ky = await kyPromise;
      return _handleResponse(ky[method], ky, args);
    };
  }

  httpClient.create = function({headers = {}, ...params}) {
    return createInstance({headers, ...params});
  };

  httpClient.extend = function({headers = {}, ...params}) {
    return createInstance({parent: kyPromise, headers, ...params});
  };

  // default async `stop` signal getter
  Object.defineProperty(httpClient, 'stop', {
    async get() {
      const ky = await kyPromise;
      return ky.stop;
    }
  });

  return httpClient;
}

async function _handleResponse(target, thisArg, args) {
  // convert legacy agent options
  args[1] = convertAgent(args[1]);

  let response;
  const [url] = args;
  try {
    response = await target.apply(thisArg, args);
  } catch(error) {
    return _handleError({error, url});
  }
  const {parseBody = true} = args[1] || {};
  // always set 'data', default to undefined
  let data;
  if(parseBody) {
    // a 204 will not include a content-type header
    const contentType = response.headers.get('content-type');
    if(contentType && contentType.includes('json')) {
      data = await response.json();
    }
  }
  Object.defineProperty(response, 'data', {value: data});
  return response;
}

/**
 * @param {object} options - Options hashmap.
 * @param {Error} options.error - Error thrown during http operation.
 * @param {string} options.url - Target URL of the request.
 *
 * @returns {Promise} Rejects with a thrown error.
 */
async function _handleError({error, url}) {
  error.requestUrl = url;

  // handle network errors and system errors that do not have a response
  if(!error.response) {
    if(error.message === 'Failed to fetch') {
      error.message = `Failed to fetch "${url}". Possible CORS error.`;
    }
    // ky's TimeoutError class
    if(error.name === 'TimeoutError') {
      error.message = `Request to "${url}" timed out.`;
    }

    throw error;
  }

  // always move status up to the root of error
  error.status = error.response.status;

  const contentType = error.response.headers.get('content-type');
  if(contentType && contentType.includes('json')) {
    const errorBody = await error.response.json();
    // the HTTPError received from ky has a generic message based on status
    // use that if the JSON body does not include a message
    error.message = errorBody.message || error.message;
    error.data = errorBody;
  }
  throw error;
}

/*!
 * Copyright (c) 2020-2026 Digital Bazaar, Inc.
 */

const httpClient = createInstance();

exports.DEFAULT_HEADERS = DEFAULT_HEADERS;
exports.httpClient = httpClient;
exports.kyPromise = kyOriginalPromise;
