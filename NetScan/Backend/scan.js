const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');
const cluster = require('cluster');
const os = require('os');

// Check if this is the master process
if (cluster.isMaster) {
  // Get the number of available CPU cores
  const numCPUs = os.cpus().length;
  
  // Fork workers based on available cores (leave 1 core free)
  const workerCount = Math.max(1, numCPUs - 1);
  console.log(`Starting ${workerCount} workers`);
  
  for (let i = 0; i < workerCount; i++) {
    cluster.fork();
  }
  
  // If a worker dies, start a new one
  cluster.on('exit', (worker) => {
    console.log(`Worker ${worker.process.pid} died, starting a new one`);
    cluster.fork();
  });
} else {
  // This is a worker process
  const app = express();
  const port = 3000;

  // Use compression middleware
  const compression = require('compression');
  app.use(compression());

  // CORS setup with more efficient configuration
  app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
  }));

  // Middleware to parse JSON request body with size limit
  app.use(express.json({ limit: '1mb' }));

  // Serve static files with caching
  app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1h',
    etag: true
  }));

  // Cache for recent scan results (simple in-memory cache)
  const resultCache = new Map();
  const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  // Allowed scan types and corresponding Nmap flags
  const allowedScans = {
    'ping': '-sP',
    'rdns': '-sn -Pn --script fcrdns',
    'headers': '--script http-headers',
    'http-vuln': '--script "http-vuln*"',
    'malware': '-sV --script=http-malware-host',
    'os-detect': '-O',
    'firewall': '-sA',
    'top-ports': '--top-ports 100',
    'tcp': '-sT',
    'udp': '-sU',
    'udp-version': '-sU -sV',
    'ping-sweep': '-sn',
    'arp': '-PR',
    'data-length': '--data-length 25'
  };

  // Validate target input (IP or hostname)
  function isValidTarget(target) {
    const ipRegex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    const hostnameRegex = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/;
    return ipRegex.test(target) || hostnameRegex.test(target);
  }

  // Endpoint for Nmap scan
  app.post('/api/scan', (req, res) => {
    const { target, scanType } = req.body;

    // Input validation
    if (!target || !scanType) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }

    if (!isValidTarget(target)) {
      return res.status(400).json({ error: 'Invalid target format' });
    }

    if (!allowedScans[scanType]) {
      return res.status(400).json({ error: 'Invalid scan type' });
    }

    // Create cache key
    const cacheKey = `${scanType}:${target}`;
    
    // Check cache first
    if (resultCache.has(cacheKey)) {
      const cachedResult = resultCache.get(cacheKey);
      console.log(`Returning cached result for ${cacheKey}`);
      return res.json({ output: cachedResult.output, fromCache: true });
    }

    // Set a timeout for the scan
    const timeoutMs = 60000; // 60 seconds
    let nmapProcess;
    let outputData = '';
    let errorData = '';
    let timedOut = false;
    
    // Using spawn instead of exec for better performance and control
    const nmapArgs = allowedScans[scanType].split(' ').filter(arg => arg);
    nmapArgs.push(target);
    
    console.log(`Running nmap ${nmapArgs.join(' ')}`);
    
    try {
      nmapProcess = spawn('nmap', nmapArgs);
      
      // Set timeout
      const timeout = setTimeout(() => {
        if (nmapProcess) {
          timedOut = true;
          nmapProcess.kill();
          res.status(408).json({ error: 'Scan timed out after 60 seconds' });
        }
      }, timeoutMs);
      
      // Collect stdout
      nmapProcess.stdout.on('data', (data) => {
        outputData += data.toString();
      });
      
      // Collect stderr
      nmapProcess.stderr.on('data', (data) => {
        errorData += data.toString();
      });
      
      // Process completion
      nmapProcess.on('close', (code) => {
        clearTimeout(timeout);
        
        if (timedOut) return; // Already responded
        
        if (code !== 0) {
          console.error(`Nmap process exited with code ${code}`);
          console.error(`Error: ${errorData}`);
          return res.status(500).json({ error: 'Error executing scan' });
        }
        
        // Cache the result
        resultCache.set(cacheKey, {
          output: outputData,
          timestamp: Date.now()
        });
        
        // Set cache cleanup timeout
        setTimeout(() => {
          if (resultCache.has(cacheKey)) {
            resultCache.delete(cacheKey);
          }
        }, CACHE_TTL);
        
        res.json({ output: outputData });
      });
      
      // Handle process errors
      nmapProcess.on('error', (err) => {
        clearTimeout(timeout);
        if (!timedOut) {
          console.error(`Failed to start nmap: ${err.message}`);
          res.status(500).json({ error: 'Failed to start scan process' });
        }
      });
    } catch (err) {
      console.error(`Exception launching nmap: ${err.message}`);
      res.status(500).json({ error: 'Failed to start scan' });
    }
  });

  // API health check endpoint
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', worker: process.pid });
  });

  // Serve the HTML UI from root path
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Scan.html'));
  });

  // Cleanup cache periodically
  setInterval(() => {
    const now = Date.now();
    for (const [key, value] of resultCache.entries()) {
      if (now - value.timestamp > CACHE_TTL) {
        resultCache.delete(key);
      }
    }
  }, 60000); // Run every minute

  // Start server
  app.listen(port, () => {
    console.log(`Worker ${process.pid}: Nmap web server running at http://localhost:${port}`);
  });
}