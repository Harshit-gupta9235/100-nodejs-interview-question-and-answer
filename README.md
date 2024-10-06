
# 100-nodejs-interview-question-and-answer
1. What is Node.js?
Answer: Node.js is a runtime environment that allows JavaScript to run on the server side. It's built on Chrome's V8 JavaScript engine, enabling fast, scalable network applications, particularly for real-time and I/O-heavy operations.
2. What are the key features of Node.js?
Answer: The key features include:
Non-blocking, asynchronous I/O.
Event-driven architecture.
Single-threaded with event looping.
Built-in libraries for HTTP, file system, etc.
Fast performance using the V8 engine.
3. What is an event-driven architecture in Node.js?
Answer: In Node.js, an event-driven architecture means the flow of the program is determined by events such as user actions, messages, or I/O. When an event occurs, a callback function is executed.
4. What is the role of the EventEmitter in Node.js?
Answer: EventEmitter is a core module in Node.js that allows objects to communicate asynchronously. It facilitates the handling of events in an event-driven model, like emitting and listening to events.
5. What is non-blocking I/O in Node.js?
Answer: Non-blocking I/O allows operations like reading from a file or database to happen asynchronously. Instead of waiting for the I/O operation to complete, Node.js moves on to the next operation and handles the result of the I/O when it’s ready, using callbacks or promises.
6. Explain the single-threaded nature of Node.js.
Answer: Node.js operates on a single-threaded event loop, but it can handle many concurrent operations using asynchronous I/O. It doesn't create new threads for every request; instead, it uses callbacks and event-driven programming to manage multiple operations concurrently.
7. What are streams in Node.js?
Answer: Streams are objects that let you read data or write data continuously in chunks. They are particularly useful for handling large amounts of data, like reading files or receiving data from network requests.
8. What are the different types of streams in Node.js?
Answer: The four types of streams are:
Readable: e.g., fs.createReadStream()
Writable: e.g., fs.createWriteStream()
Duplex: both readable and writable, e.g., sockets
Transform: modifies the data as it is read or written, e.g., zlib streams.
9. What is the difference between synchronous and asynchronous programming in Node.js?
Answer: Synchronous programming waits for each operation to complete before moving to the next one, blocking the execution. Asynchronous programming allows operations to happen independently, using callbacks, promises, or async/await to handle the results when they are available.
10. How do you handle errors in Node.js?
Answer: Errors in Node.js can be handled using:
Error-first callbacks (e.g., callback(err, result)).
Promises (e.g., .catch() method).
try/catch block for handling exceptions in async/await.
11. What is middleware in Express.js?
Answer: Middleware in Express.js is a function that can access the request object (req), response object (res), and the next middleware function in the application's request-response cycle. Middleware functions can execute code, modify the request and response, end the request-response cycle, or pass control to the next middleware.
12. How do you define a middleware function in Express.js?
Answer: A middleware function in Express is defined like this:
javascript
Copy code
app.use((req, res, next) => {
  console.log('Middleware called');
  next();
});
13. What are some built-in middleware in Express.js?
Answer: Common built-in middleware includes:
express.json(): Parses incoming JSON requests.
express.urlencoded(): Parses URL-encoded payloads.
express.static(): Serves static files like HTML, CSS, images.
14. What is routing in Express.js?
Answer: Routing refers to how an application responds to client requests for different endpoints (paths) with specific HTTP methods like GET, POST, PUT, DELETE.
15. How do you define a route in Express.js?
Answer: A route can be defined as follows:
javascript
Copy code
app.get('/path', (req, res) => {
  res.send('Response to GET request');
});
16. What is the role of the next() function in Express middleware?
Answer: The next() function is used to pass control to the next middleware function in the stack. If not called, the request-response cycle will be left hanging.
17. What is the difference between app.use() and app.get() in Express.js?
Answer: app.use() is used to apply middleware to all HTTP methods, while app.get() is used to define routes that handle only GET requests.
18. What are the HTTP methods supported by Express.js?
Answer: Express.js supports standard HTTP methods like GET, POST, PUT, DELETE, PATCH, HEAD, and OPTIONS.
19. What is the difference between PUT and POST in RESTful APIs?
Answer: POST is used to create new resources, whereas PUT is used to update an existing resource or create it if it does not exist.
20. How do you handle form data in Express.js?
Answer: You can handle form data by using the express.urlencoded() middleware to parse URL-encoded bodies:
javascript
Copy code
app.use(express.urlencoded({ extended: true }));
21. What is CORS and how do you enable it in Express.js?
Answer: CORS (Cross-Origin Resource Sharing) is a mechanism to allow or restrict resources on a web server depending on the origin of the request. You can enable CORS in Express.js using the cors middleware:
javascript
Copy code
const cors = require('cors');
app.use(cors());
22. What is a promise in Node.js?
Answer: A promise is an object that represents the eventual completion (or failure) of an asynchronous operation and its resulting value. It has three states: pending, fulfilled, and rejected.
23. What is async/await in Node.js?
Answer: async/await is syntactic sugar over promises, making asynchronous code easier to read and write. Functions marked as async return a promise, and await pauses the execution until the promise resolves or rejects.
24. How do you read and write files in Node.js?
Answer: You can read files using fs.readFile() and write using fs.writeFile():
javascript
Copy code
const fs = require('fs');
fs.readFile('file.txt', 'utf8', (err, data) => {
  if (err) throw err;
  console.log(data);
});
25. What is process.nextTick() in Node.js?
Answer: process.nextTick() is used to defer the execution of a function until the next iteration of the event loop, giving it higher priority than I/O operations.
26. What is a RESTful API?
Answer: A RESTful API (Representational State Transfer) is an architectural style that uses HTTP methods (GET, POST, PUT, DELETE) to manipulate resources identified by URIs.
27. How do you create a simple RESTful API in Express.js?
Answer: Here's a basic example:
javascript
Copy code
const express = require('express');
const app = express();

app.get('/api/resource', (req, res) => {
  res.json({ message: 'GET request' });
});

app.post('/api/resource', (req, res) => {
  res.json({ message: 'POST request' });
});

app.listen(3000);
28. What are query parameters in Express.js?
Answer: Query parameters are key-value pairs that appear after the question mark in a URL. They can be accessed using req.query:
javascript
Copy code
app.get('/search', (req, res) => {
  const { query } = req.query;
  res.send(`You searched for ${query}`);
});
29. What are route parameters in Express.js?
Answer: Route parameters are named segments of the URL that act as placeholders for dynamic values. They can be accessed using req.params:
javascript
Copy code
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  res.send(`User ID is ${userId}`);
});
30. What is the package.json file in Node.js?
Answer: The package.json file holds metadata relevant to the project and manages project dependencies. It includes details like the name, version, scripts, and list of dependencies.
31. How do you manage dependencies in a Node.js project?
Answer: Dependencies are managed using npm or yarn. You can install packages using:
bash
Copy code
npm install <package-name>
The installed packages will be listed under the dependencies section of the package.json file.
32. What is the node_modules folder in Node.js?
Answer: The node_modules folder contains the installed dependencies of your Node.js project. It is automatically generated when you run npm install or yarn install.
33. What is the role of the npm tool in Node.js?
Answer: npm (Node Package Manager) is a tool that helps manage packages (libraries, tools, frameworks) in a Node.js application. It allows you to install, update, and uninstall packages, as well as manage their versions.
34. What is the difference between dependencies and devDependencies in package.json?
Answer: dependencies are the libraries your project needs to run, while devDependencies are libraries needed only for development purposes, such as testing frameworks. You can install a dev dependency using npm install <package-name> --save-dev.
35. What is the res.json() method in Express.js?
Answer: res.json() is a method used to send a JSON response back to the client. It automatically sets the Content-Type header to application/json.
36. What is the res.send() method in Express.js?
Answer: res.send() is used to send a response of various types (string, object, buffer) to the client. It automatically sets the appropriate Content-Type header.
37. What is the res.status() method in Express.js?
Answer: res.status() sets the HTTP status code for the response. For example:
javascript
Copy code
res.status(404).send('Not Found');
38. How can you serve static files in Express.js?
Answer: You can use express.static() middleware to serve static files like images, CSS, or JavaScript files:
javascript
Copy code
app.use(express.static('public'));
39. What is body parsing in Express.js?
Answer: Body parsing refers to extracting data from the body of HTTP requests, particularly POST or PUT requests. Express.js has middleware like express.json() and express.urlencoded() for parsing JSON and URL-encoded bodies.
40. What is the app.listen() method in Express.js?
Answer: app.listen() is used to bind and listen for connections on a specified host and port. It starts the server:
javascript
Copy code
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
41. What is the next(err) function in Express.js?
Answer: next(err) passes control to the next error-handling middleware. If an error occurs, calling next(err) will skip over normal middleware and trigger error-handling middleware.
42. How do you handle errors globally in Express.js?
Answer: Error-handling middleware is defined as a function with four arguments: err, req, res, and next:
javascript
Copy code
app.use((err, req, res, next) => {
  res.status(500).send('Something broke!');
});
43. What is the purpose of try/catch in async/await in Node.js?
Answer: try/catch is used in combination with async/await to handle errors that may occur in asynchronous code, as promises do not throw exceptions directly.
44. How do you handle file uploads in Express.js?
Answer: You can handle file uploads in Express using libraries like multer:
javascript
Copy code
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
  res.send('File uploaded');
});
45. What is a session in Express.js?
Answer: A session is a way to store data that persists across requests from a user. Express can handle sessions using express-session middleware, which stores session data server-side.
46. How do you implement sessions in Express.js?
Answer: You can use the express-session middleware for session management:
javascript
Copy code
const session = require('express-session');
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true,
}));
47. . What is JWT (JSON Web Token) and how is it used in Node.js?
Answer: JWT is a token format used for securely transmitting information between parties. In Node.js, it is commonly used for authentication. You can use the jsonwebtoken package to sign and verify tokens.
48. How do you implement JWT authentication in Express.js?
Answer: Here’s a simple implementation:
javascript
Copy code
const jwt = require('jsonwebtoken');
const secret = 'your-secret-key';

app.post('/login', (req, res) => {
  const token = jwt.sign({ userId: req.body.userId }, secret);
  res.json({ token });
});

app.get('/protected', (req, res) => {
  const token = req.headers['authorization'];
  if (token) {
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        return res.status(401).send('Unauthorized');
      }
      res.send('Protected content');
    });
  } else {
    res.status(401).send('Unauthorized');
  }
});
49. What is socket programming in Node.js?
Answer: Socket programming allows real-time communication between a client and a server. It is often implemented using WebSocket or libraries like Socket.io for two-way communication.
50. How do you implement real-time communication in Node.js using Socket.io?
Answer: Here’s a basic example using Socket.io:
javascript
Copy code
const io = require('socket.io')(server);
io.on('connection', (socket) => {
  console.log('A user connected');
  socket.on('message', (msg) => {
    io.emit('message', msg);
  });
});
51. What is the difference between readFileSync and readFile in Node.js?
Answer: readFileSync is a synchronous function that blocks execution until the file is read, while readFile is asynchronous and uses a callback to handle the result.
52. What is the cluster module in Node.js?
Answer: The cluster module allows Node.js to create child processes (workers) that share the same server port. This is used to take advantage of multi-core systems.
53. What is middleware chaining in Express.js?
Answer: Middleware chaining refers to passing control from one middleware function to another using the next() function. Each middleware can perform an operation or modify the request/response objects before passing control to the next function.
54. What is cookie-parser in Express.js?
Answer: cookie-parser is middleware used to parse cookies from the Cookie header and make them available in req.cookies.
55. How do you implement role-based authentication in Express.js?
Answer: You can implement role-based authentication by checking the user's role in middleware before allowing access to certain routes:
javascript
Copy code
function authorize(roles = []) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send('Forbidden');
    }
    next();
  };
}

app.get('/admin', authorize(['admin']), (req, res) => {
  res.send('Admin access');
});
56. What are WebSockets, and how do they differ from HTTP?
Answer: WebSockets provide full-duplex communication between the client and server over a single, long-lived connection. Unlike HTTP, which is request-response based, WebSockets allow for continuous, real-time communication.
57. How do you debug Node.js applications?
Answer: You can debug Node.js applications using the --inspect flag with node, along with Chrome DevTools or VS Code debugger:
bash
Copy code
node --inspect index.js
58. What is the event loop in Node.js?
Answer: The event loop is the mechanism that allows Node.js to perform non-blocking I/O operations by offloading operations to the system's kernel whenever possible.
59. What is the async module in Node.js?
Answer: The async module provides utility functions for working with asynchronous JavaScript, such as waterfall, series, parallel, etc., which simplify control flow when working with async tasks.
60. What is the nodemon tool in Node.js?
Answer: nodemon is a tool that automatically restarts the Node.js application when file changes are detected, useful for development.
61. What is the difference between path.join() and path.resolve() in Node.js?
Answer:
path.join() joins all given path segments into one normalized path, resolving . and .. segments.
path.resolve() resolves a sequence of paths into an absolute path by considering the current working directory and handling .. and . in the process.
62. What is req.body in Express.js?
Answer: req.body contains the parsed body of the incoming request, typically when using POST or PUT methods. For this to work, body-parsing middleware like express.json() or express.urlencoded() needs to be used.
63. How do you perform logging in Node.js applications?
Answer: Logging in Node.js can be done using the built-in console methods (console.log(), console.error()) or using dedicated libraries like winston or morgan for more structured logging.
64. How do you use morgan in Express.js for logging?
Answer: morgan is an HTTP request logger middleware for Node.js. You can set it up in an Express application like this:
javascript
Copy code
const morgan = require('morgan');
app.use(morgan('combined'));
65. What is the helmet module in Express.js, and why is it used?
Answer: helmet is a collection of middleware functions that help secure Express apps by setting various HTTP headers (like X-Frame-Options, XSS Protection). It's used to harden security against common web vulnerabilities.
66. What is the crypto module in Node.js?
Answer: The crypto module provides cryptographic functionality in Node.js, such as hashing, encryption, and decryption. It includes methods for working with ciphers, hashes, HMAC, digital signatures, etc.
67. How do you hash passwords in Node.js?
Answer: You can hash passwords using the bcrypt library:
javascript
Copy code
const bcrypt = require('bcrypt');
const saltRounds = 10;

bcrypt.hash('myPassword', saltRounds, (err, hash) => {
  if (err) throw err;
  console.log(hash);
});
68. What is the fs module in Node.js?
Answer: The fs module provides an API for interacting with the file system in Node.js, allowing operations such as reading, writing, updating, and deleting files.
69. What is dotenv, and how is it used in Node.js applications?
Answer: dotenv is a module that loads environment variables from a .env file into process.env. It's useful for managing environment-specific variables like API keys and database credentials:
javascript
Copy code
require('dotenv').config();
console.log(process.env.API_KEY);
70. What is a buffer in Node.js?
Answer: A buffer is a temporary holding spot for binary data in Node.js. It's primarily used for handling binary streams like reading from a file or receiving packets over a network.
71. What is an API gateway, and why is it useful in Node.js applications?
Answer: An API gateway acts as a reverse proxy to multiple services, routing API requests, handling cross-cutting concerns like authentication, rate limiting, logging, and transforming requests and responses. It's useful in microservices architecture to centralize API management.
72. How do you validate user input in an Express.js application?
Answer: You can use libraries like express-validator to validate and sanitize user inputs:
javascript
Copy code
const { check, validationResult } = require('express-validator');

app.post('/user', [
  check('email').isEmail(),
  check('password').isLength({ min: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  res.send('User created');
});
73. What is rate limiting, and how do you implement it in Express.js?
Answer: Rate limiting controls the number of requests a user or IP can make within a certain time period to protect APIs from abuse or denial-of-service attacks. You can implement it using the express-rate-limit package:
javascript
Copy code
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per window
});
app.use(limiter);
74. What is graceful shutdown in Node.js, and how do you implement it?
Answer: Graceful shutdown is the process of shutting down a Node.js application without abruptly terminating active requests. You can implement it by listening for SIGINT or SIGTERM signals and closing the server gracefully:
javascript
Copy code
process.on('SIGTERM', () => {
  server.close(() => {
    console.log('Process terminated');
  });
});
75. What is the difference between fork() and spawn() in Node.js?
Answer:
fork() is used to create a new Node.js process, while establishing an IPC (Inter-Process Communication) channel for communication between the parent and child processes.
spawn() is used to launch a new process, but does not create a communication channel.
76. How do you make an HTTP request in Node.js?
Answer: You can make an HTTP request using the built-in http or https modules, or third-party libraries like axios or node-fetch. For example, using axios:
javascript
Copy code
const axios = require('axios');
axios.get('https://api.example.com/data')
  .then(response => console.log(response.data))
  .catch(error => console.log(error));
77. What is a reverse proxy, and how is it used in Node.js?
Answer: A reverse proxy is a server that sits between clients and backend services, routing client requests to the appropriate service. It can handle load balancing, caching, and security. In Node.js, reverse proxy functionality can be implemented using libraries like http-proxy-middleware.
78. What is process.env, and why is it important in Node.js?
Answer: process.env is a global object that stores environment variables in Node.js. It's important for configuring the application in different environments (development, production, testing) without hardcoding sensitive information like API keys and credentials.
79. How do you prevent SQL injection in Node.js applications?
Answer: SQL injection can be prevented by:
Using parameterized queries or prepared statements with libraries like pg (for PostgreSQL) or mysql2.
Avoiding dynamic queries that concatenate user inputs directly into SQL statements.
80. What is the purpose of the async library in Node.js?
Answer: The async library provides utility functions for handling asynchronous operations, like running tasks in series, parallel, or waterfall (where each task depends on the previous one), making callback hell easier to manage.
81. How do you schedule tasks in Node.js?
Answer: You can schedule tasks in Node.js using libraries like node-cron or agenda for periodic jobs. For example, with node-cron:
javascript
Copy code
const cron = require('node-cron');
cron.schedule('0 0 * * *', () => {
  console.log('Task runs every midnight');
});
82. What is the purpose of npm and yarn lock files?
Answer: package-lock.json (for npm) and yarn.lock (for yarn) ensure that the same package versions are installed across all environments, maintaining consistency in dependency versions.
83. What is the difference between npm install and npm ci?
Answer:
npm install installs dependencies listed in package.json, and if package-lock.json exists, it tries to match the versions listed there.
npm ci installs exactly the versions listed in package-lock.json, and it’s faster and more reliable for continuous integration environments.
84. How do you perform unit testing in a Node.js application?
Answer: You can perform unit testing using libraries like Mocha or Jest. Here’s an example using Mocha and Chai:
javascript
Copy code
const chai = require('chai');
const expect = chai.expect;

describe('Math operations', () => {
  it('should add two numbers', () => {
    expect(2 + 2).to.equal(4);
  });
});
85. What is cross-site scripting (XSS), and how do you prevent it in Node.js?
Answer: XSS is a type of security vulnerability where attackers inject malicious scripts into web applications. You can prevent XSS by:
Validating and sanitizing user inputs.
Escaping special characters in HTML templates.
Using libraries like DOMPurify for sanitizing HTML.
86. What is the difference between blocking and non-blocking code in Node.js?
Answer: Blocking code waits for an operation to complete before continuing to the next one, while non-blocking code continues executing without waiting, handling the result via callbacks or promises. Node.js is designed for non-blocking I/O operations.
87. What is an ETag, and how does it work?
Answer: An ETag (Entity Tag) is an HTTP header used for caching purposes. It represents a version of a resource and helps to determine whether the resource has changed. If the ETag matches, the resource has not changed, and the server can respond with a 304 Not Modified status.
88. How do you secure an Express.js application?
Answer: To secure an Express app:
Use HTTPS.
Set HTTP headers with helmet.
Validate and sanitize user inputs.
Implement rate limiting to prevent DDoS attacks.
Store sensitive data (like passwords) securely (e.g., hashing).
Protect against XSS and CSRF attacks.
89. What is the difference between horizontal and vertical scaling in Node.js?
Answer:
Horizontal scaling involves adding more machines to distribute the load.
Vertical scaling involves increasing the capacity of a single machine (e.g., more CPU, RAM).
90. What is a virtual machine (VM) and how does it differ from a container?
Answer: A virtual machine emulates an entire operating system, with its own kernel, running on a host machine. A container, like Docker, shares the host's OS kernel but isolates the application environment. Containers are generally more lightweight and efficient than VMs.
91. What is CSRF, and how do you prevent it in Node.js?
Answer: Cross-Site Request Forgery (CSRF) is an attack where unauthorized commands are transmitted from a user that the server trusts. You can prevent it using anti-CSRF tokens that are included in forms and validated on the server-side.
92. What are streams in Node.js?
Answer: Streams are objects that allow you to read data or write data in chunks, rather than loading all data into memory at once. They are useful for handling large data, such as files or HTTP requests.
93. How does stream.pipe() work in Node.js?
Answer: stream.pipe() is used to pass the output of one stream as input to another stream, allowing you to chain streams together. For example, reading a file and writing it to an HTTP response:
javascript
Copy code
const fs = require('fs');
const readStream = fs.createReadStream('file.txt');
readStream.pipe(res);
94. What is the cors middleware in Express.js?
Answer: The cors middleware enables Cross-Origin Resource Sharing (CORS), allowing your API to be accessible from other domains. You can configure it like this:
javascript
Copy code
const cors = require('cors');
app.use(cors());
95. What is the role of middleware in Express.js?
Answer: Middleware functions in Express.js are functions that have access to the request and response objects. They can modify the request, end the response, or pass control to the next middleware in the stack using next().
96. What is the difference between middleware and routing in Express.js?
Answer: Middleware functions are called before the route handler and can modify the request or response. Routes define the endpoints of your API and their respective HTTP methods (GET, POST, etc.).
97. What is the difference between PUT and PATCH in RESTful APIs?
Answer:
PUT is used to update a resource by replacing it entirely.
PATCH is used to partially update a resource, only modifying certain fields.
98. What is a RESTful API?
Answer: A RESTful API is an architectural style for designing networked applications that uses HTTP requests to access and manipulate data. It is stateless and typically uses standard HTTP methods like GET, POST, PUT, DELETE.
99. How do you handle CORS errors in Node.js?
Answer: CORS errors occur when a browser blocks a request from a different origin due to the same-origin policy. You can handle it using the cors middleware in Express:
javascript
Copy code
const cors = require('cors');
app.use(cors({ origin: 'http://example.com' }));
100. What is Docker, and how is it used in Node.js development?
Answer: Docker is a platform that allows you to package applications and their dependencies into containers, ensuring consistent environments across development, testing, and production. In Node.js development, Docker is used to create isolated environments that run Node.js applications with all necessary dependencies, making deployment simpler and more scalable.
