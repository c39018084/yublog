const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  // Disable webpack hot module replacement
  if (process.env.NODE_ENV === 'development') {
    // Override webpack dev server to disable websockets
    app.use('/__webpack_hmr', (req, res, next) => {
      res.status(404).end();
    });
    
    app.use('/ws', (req, res, next) => {
      res.status(404).end();
    });
    
    app.use('/sockjs-node', (req, res, next) => {
      res.status(404).end();
    });
  }
}; 