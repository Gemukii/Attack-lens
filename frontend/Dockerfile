FROM node:22-alpine3.23 AS build

WORKDIR /app

RUN apk upgrade --no-cache

RUN chown node:node /app

COPY --chown=node:node package*.json ./

USER node

RUN npm ci --legacy-peer-deps --ignore-scripts

COPY --chown=node:node . .

RUN npm run postinstall \
	&& npm run build

FROM node:22-alpine3.23 AS runtime

WORKDIR /app

ENV NODE_ENV=production \
	HOST=0.0.0.0 \
	PORT=3000

COPY --from=build --chown=node:node /app/.output ./.output

USER node

EXPOSE 3000

CMD ["node", ".output/server/index.mjs"]