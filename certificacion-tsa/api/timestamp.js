import https from 'https';

function crearTimeStampReq(hashHex) {
    const hash = Buffer.from(hashHex, 'hex');
    const sha256OID = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]);
    const algorithmIdentifier = Buffer.concat([Buffer.from([0x30, sha256OID.length]), sha256OID]);
    const octetString = Buffer.concat([Buffer.from([0x04, 0x20]), hash]);
    const messageImprint = Buffer.concat([Buffer.from([0x30, algorithmIdentifier.length + octetString.length]), algorithmIdentifier, octetString]);
    const version = Buffer.from([0x02, 0x01, 0x01]);
    const content = Buffer.concat([version, messageImprint]);
    return Buffer.concat([Buffer.from([0x30, content.length]), content]);
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
    
    const { hash } = req.body;
    if (!hash || hash.length !== 64) return res.status(400).json({ error: 'Hash inválido' });
    
    try {
        const tsq = crearTimeStampReq(hash);
        const options = {
            hostname: 'freetsa.org',
            port: 443,
            path: '/tsr',
            method: 'POST',
            headers: {
                'Content-Type': 'application/timestamp-query',
                'Content-Length': tsq.length
            },
            timeout: 15000
        };
        
        const response = await new Promise((resolve, reject) => {
            const request = https.request(options, (resp) => {
                let data = [];
                resp.on('data', chunk => data.push(chunk));
                resp.on('end', () => resolve({ status: resp.statusCode, data: Buffer.concat(data) }));
            });
            request.on('error', reject);
            request.on('timeout', () => { request.destroy(); reject(new Error('Timeout')); });
            request.write(tsq);
            request.end();
        });
        
        if (response.status !== 200) throw new Error(`TSA error ${response.status}`);
        
        res.status(200).json({
            success: true,
            tsrBase64: response.data.toString('base64'),
            timestamp: new Date().toISOString(),
            emisor: 'FREETSA.org',
            algoritmo: 'SHA256'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}