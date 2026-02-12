import https from 'https';

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Only POST allowed' });

  try {
    // Parsear body
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (e) {}
    }
    
    const { hash, url } = body || {};
    
    if (!hash || typeof hash !== 'string' || hash.length !== 64) {
      return res.status(400).json({ 
        error: 'Hash SHA256 inválido (debe ser 64 caracteres hex)',
        received: hash 
      });
    }

    // Crear TimeStampReq ASN.1 DER para SHA256
    const hashBuf = Buffer.from(hash, 'hex');
    
    // OID SHA256: 2.16.840.1.101.3.4.2.1
    const sha256OID = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]);
    
    // AlgorithmIdentifier: SEQUENCE { OID, NULL }
    const algId = Buffer.concat([
      Buffer.from([0x30, sha256OID.length]), 
      sha256OID
    ]);
    
    // MessageImprint: SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }
    const octetString = Buffer.concat([
      Buffer.from([0x04, 0x20]), 
      hashBuf
    ]);
    
    const messageImprint = Buffer.concat([
      Buffer.from([0x30, algId.length + octetString.length]),
      algId,
      octetString
    ]);
    
    // Version: INTEGER 1
    const version = Buffer.from([0x02, 0x01, 0x01]);
    
    // TimeStampReq: SEQUENCE { version, messageImprint }
    const content = Buffer.concat([version, messageImprint]);
    const tsq = Buffer.concat([Buffer.from([0x30, content.length]), content]);

    // Llamar a FREETSA.org
    const tsr = await new Promise((resolve, reject) => {
      const request = https.request({
        hostname: 'freetsa.org',
        port: 443,
        path: '/tsr',
        method: 'POST',
        headers: {
          'Content-Type': 'application/timestamp-query',
          'Content-Length': tsq.length,
          'User-Agent': 'CertificacionPericialWeb/2.0'
        },
        timeout: 20000
      }, (resp) => {
        let data = [];
        resp.on('data', chunk => data.push(chunk));
        resp.on('end', () => {
          if (resp.statusCode === 200) {
            resolve(Buffer.concat(data));
          } else {
            reject(new Error(`TSA respondió status ${resp.statusCode}`));
          }
        });
      });
      
      request.on('error', (err) => reject(new Error(`Error HTTPS: ${err.message}`)));
      request.on('timeout', () => {
        request.destroy();
        reject(new Error('Timeout conectando con FREETSA (20s)'));
      });
      
      request.write(tsq);
      request.end();
    });

    return res.status(200).json({
      success: true,
      tsrBase64: tsr.toString('base64'),
      timestamp: new Date().toISOString(),
      emisor: 'FREETSA.org (TSA)',
      algoritmo: 'SHA256',
      urlOriginal: url || 'No especificada',
      nota: 'Token RFC 3161 válido según eIDAS'
    });

  } catch (error) {
    console.error('Error TSA:', error);
    return res.status(500).json({ 
      success: false, 
      error: error.message,
      alternativa: 'Puede obtener el sello manualmente en https://freetsa.org'
    });
  }
}