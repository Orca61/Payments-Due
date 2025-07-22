const jwt = require('jsonwebtoken');



const PIN = process.env.PIN || '65136129'; // Use env variable for security


const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';


const MAX_ATTEMPTS = 5;


let attempts = 0;


let lockoutUntil = null;



module.exports = async (req, res) => {


  if (req.method !== 'POST') {


    return res.status(405).json({ error: 'Method not allowed' });


  }



  const { pin } = req.body;



  if (!pin) {


    return res.status(400).json({ error: 'PIN is required' });


  }



  if (lockoutUntil && Date.now() < lockoutUntil) {


    return res.status(429).json({ error: 'Too many attempts. Try again in 5 minutes.' });


  }



  if (pin === PIN) {


    attempts = 0;


    lockoutUntil = null;


    const token = jwt.sign({ authenticated: true }, JWT_SECRET, { expiresIn: '30m' });


    return res.status(200).json({ token });


  } else {


    attempts++;


    if (attempts >= MAX_ATTEMPTS) {


      lockoutUntil = Date.now() + 5 * 60 * 1000; // 5-minute lockout


      return res.status(429).json({ error: 'Too many attempts. Try again in 5 minutes.' });


    }


    return res.status(401).json({ error: `Incorrect PIN. ${MAX_ATTEMPTS - attempts} attempts remaining.` });


  }


};

