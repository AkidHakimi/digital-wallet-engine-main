import 'dotenv/config';
import express from 'express';
import {requireAdminKey} from './auth.js';
import {createTenant, listTenants, updateTenant, createApiKey, revokeApiKey, listApiKeys} from './routes.js';

const app  = express();
const PORT = process.env.ADMIN_PORT || 3000;

app.use(express.json());
app.use(requireAdminKey);

app.post('/tenants',                          createTenant);
app.get('/tenants',                           listTenants);
app.patch('/tenants/:id',                     updateTenant);
app.post('/tenants/:id/api-keys',             createApiKey);
app.delete('/tenants/:id/api-keys/:keyId',    revokeApiKey);
app.get('/tenants/:id/api-keys',              listApiKeys);

app.listen(PORT, () => console.log(`[Admin] running on http://localhost:${PORT}`));
