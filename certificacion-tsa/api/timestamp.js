export default async function handler(req, res) {
  // CORS headers esenciales
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Only POST allowed' });

  try {
    // Parsear body manualmente si es string
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (e) {}
    }
    
    const { hash } = body || {};
    if (!hash || hash.length !== 64) {
      return res.status(400).json({ error: 'Hash SHA256 inválido (64 chars hex requerido)' });
    }

    // Importar https dentro de la función para Vercel
    const https = require('https');
    
    // Crear TimeStampReq ASN.1
    const hashBuf = Buffer.from(hash, 'hex');
    const sha256OID = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]);
    const algId = Buffer.concat([Buffer.from([0x30, sha256OID.length]), sha256OID]);
    const octet = Buffer.concat([Buffer.from([0x04, 0x20]), hashBuf]);
    const msgImp = Buffer.concat([Buffer.from([0x30, algId.length + octet.length]), algId, octet]);
    const ver = Buffer.from([0x02, 0x01, 0x01]);
    const content = Buffer.concat([ver, msgImp]);
    const tsq = Buffer.concat([Buffer.from([0x30, content.length]), content]);

    // Llamar a FREETSA
    const tsr = await new Promise((resolve, reject) => {
      const request = https.request({
        hostname: 'freetsa.org',
        port: 443,
        path: '/tsr',
        method: 'POST',
        headers: {
          'Content-Type': 'application/timestamp-query',
          'Content-Length': tsq.length
        },
        timeout: 20000
      }, (resp) => {
        let data = [];
        resp.on('data', chunk => data.push(chunk));
        resp.on('end', () => {
          if (resp.statusCode === 200) resolve(Buffer.concat(data));
          else reject(new Error(`Status ${resp.statusCode}`));
        });
      });
      request.on('error', reject);
      request.on('timeout', () => { request.destroy(); reject(new Error('Timeout')); });
      request.write(tsq);
      request.end();
    });

    return res.status(200).json({
      success: true,
      tsrBase64: tsr.toString('base64'),
      timestamp: new Date().toISOString(),
      emisor: 'FREETSA.org (TSA)',
      algoritmo: 'SHA256'
    });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ 
      success: false, 
      error: error.message,
      nota: 'FREETSA puede estar saturado. Intente de nuevo en 30 segundos.'
    });
  }
}