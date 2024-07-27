# Single-file Express.js User-Backend with Email password resets

### Get started
After cloning the repository, run ´´´npm install´´´ to install necessary dependencies.
Next, search for ```!CHANGE``` in the server.js file and change these properties to your liking. Most of these **have** to be changed, as they are important credentials.
Finally, run the project using ```node server.js```.

### What makes this template / boilerplate special
This is the most simplistic form of a functional account backend with proper registration, longins, authentication ("bearer") tokens and password resets via email. 

### Database setup
 This boilerplate expects a basic MySQL database setup with:
    1 - A table named "accounts"
    2 - The follwing columns in said table:
        1. id (bigint)
        2. created_at (datetime)
        3. email (varchar(255))
        4. password (varchar(255))
        5. user_name (varchar(255)

## Resources
[What is a JWT Token?](https://jwt.io/introduction)
[What is a password hash?](https://www.techtarget.com/searchdatamanagement/definition/hashing)
[Get started with Express.js](https://expressjs.com/en/starter/hello-world.html)
[How to install Node.js](https://nodejs.org/en/learn/getting-started/how-to-install-nodejs)
[Work with queries](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams)