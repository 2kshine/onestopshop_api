#Take Base image and tweak a bit to have our custom image run in it
FROM node:18
WORKDIR /app
#Since workdir is pointer to a dir so only . is fine
# if any of these layers steps change, lets say if 6 is changed, all the steps after that is going to re run
COPY package.json ./
RUN npm install
#argument NODE_ENV value is going to be passed from docker compose environment file.
ARG NODE_ENV
#then based on that scenario do the conditional.
RUN if [ "$NODE_ENV" = "development" ]; \
        then npm install; \
        else npm install --only=production; \
        fi

#copy rest of the code step 9, if only source code is changed, we dont have to run step 7 in every change. 
COPY . .
#Expose port is for documentation purposes
EXPOSE 8080
CMD ["node", "server.js"]
