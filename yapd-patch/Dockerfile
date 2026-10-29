FROM leufrasiojunior/yapd@sha256:32f46a45687e324087002b088343ad30552d9d1da4fb011feaa5e926ed9d4f6e
COPY tsconfig.base.json /app/tsconfig.base.json
COPY identity-provider.ts identity-provider.spec.ts /app/apps/api/src/integrations/
COPY patched/clients.service.ts /app/apps/api/src/clients/clients.service.ts
COPY patched/queries.service.ts /app/apps/api/src/queries/queries.service.ts
RUN cd /app/apps/api && node --import tsx --test src/integrations/identity-provider.spec.ts && npm run build
