FROM node:14

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./

RUN npm install

# Bundle app source
COPY . .

# Change the port if needed
EXPOSE 3000

# Run the node command with server.js to start it
CMD [ "node", "server.js" ]