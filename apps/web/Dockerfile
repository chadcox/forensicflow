FROM node:26-alpine

WORKDIR /app

COPY apps/web/package.json ./
RUN npm install

COPY apps/web ./

# Drop root: the image ships a non-privileged `node` user.
RUN chown -R node:node /app
USER node

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
