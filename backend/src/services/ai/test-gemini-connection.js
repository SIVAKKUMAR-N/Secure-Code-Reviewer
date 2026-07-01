const { GoogleGenerativeAI } = require('@google/generative-ai');
const dotenv = require('dotenv');
const path = require('path');
dotenv.config({ path: path.join(__dirname, '../../../.env') });

const apiKey = process.env.GEMINI_API_KEY;
console.log('Using API Key:', apiKey ? (apiKey.slice(0, 8) + '...') : 'undefined');

if (!apiKey) {
  console.error('No GEMINI_API_KEY found in .env');
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(apiKey);
const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

const prompt = `Hello, reply with "Gemini is working!" if you receive this.`;

async function run() {
  try {
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    console.log('Response:', text);
  } catch (error) {
    console.error('Gemini connection failed:', error.message);
  }
}

run();
