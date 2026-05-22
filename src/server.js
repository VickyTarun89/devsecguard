import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { runRemediationSequence } from './remediator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 8422;

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // --- API Endpoints ---
  
  // GET /api/scan
  if (req.method === 'GET' && pathname === '/api/scan') {
    const scanPath = url.searchParams.get('path') || process.cwd();
    const result = await runRemediationSequence({ scanDir: scanPath, clean: false });
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  // POST /api/clean
  if (req.method === 'POST' && pathname === '/api/clean') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', async () => {
      let scanPath = process.cwd();
      try {
        if (body) {
          const parsed = JSON.parse(body);
          if (parsed.path) scanPath = parsed.path;
        }
      } catch (e) {
        // use default path if body parse fails
      }

      const result = await runRemediationSequence({ scanDir: scanPath, clean: true });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    });
    return;
  }

  // --- Static File Serving ---
  let filePath = '';
  if (pathname === '/') {
    filePath = path.join(__dirname, '../public/index.html');
  } else {
    filePath = path.join(__dirname, '../public', pathname);
  }

  // Prevent Directory Traversal Attacks
  const publicDir = path.join(__dirname, '../public');
  const relative = path.relative(publicDir, filePath);
  const isSafe = relative && !relative.startsWith('..') && !path.isAbsolute(relative);

  if (pathname !== '/' && !isSafe) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Access Denied');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('File Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`================================================================`);
  console.log(` DevSecGuard Web Server is running locally!`);
  console.log(` Open your browser and navigate to: http://127.0.0.1:${PORT}`);
  console.log(` Click Ctrl+C in this terminal to stop the server.`);
  console.log(`================================================================`);
});
