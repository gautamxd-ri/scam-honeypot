from flask import Flask, request, jsonify
from openai import OpenAI
import os
import re
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Initialize OpenAI - it will read OPENAI_API_KEY from .env file
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Your API key for authentication - read from .env file
YOUR_API_KEY = os.getenv('YOUR_API_KEY')

# Store conversations in memory
conversations = {}


def check_api_key(request):
    """Verify API key from request"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return False
    
    token = auth_header.replace('Bearer ', '').strip()
    return token == YOUR_API_KEY


def detect_scam(message):
    """Detect if message is a scam"""
    scam_keywords = [
        'congratulations', 'won', 'prize', 'lottery', 'claim', 'winner',
        'urgent', 'verify', 'account', 'suspended', 'expire', 'blocked',
        'click here', 'limited time', 'act now', 'free money', 'cash prize',
        'bank details', 'upi', 'transfer', 'reward', 'confirm identity',
        'otp', 'cvv', 'card number', 'pin', 'password', 'security code',
        'bit.ly', 'shortened link', 'update payment', 'refund', 'emi'
    ]
    
    message_lower = message.lower()
    
    # Count matching keywords
    matches = [keyword for keyword in scam_keywords if keyword in message_lower]
    scam_score = len(matches)
    
    # Check for URLs (common in scams)
    has_url = bool(re.search(r'https?://|www\.|bit\.ly', message_lower))
    if has_url:
        scam_score += 2
    
    # Calculate confidence (0 to 1)
    confidence = min(scam_score / 5.0, 1.0)
    is_scam = confidence > 0.25
    
    return is_scam, round(confidence, 2), matches


def extract_intelligence(conversation_text):
    """Extract sensitive information from conversation"""
    
    # Bank account numbers (Indian format: 9-18 digits)
    bank_accounts = re.findall(r'\b\d{9,18}\b', conversation_text)
    
    # UPI IDs (format: name@bank or phonenumber@upi)
    upi_ids = re.findall(r'\b[\w.-]+@[\w.-]+\b', conversation_text)
    # Filter to only UPI-like patterns
    upi_ids = [upi for upi in upi_ids if any(bank in upi.lower() for bank in 
                ['paytm', 'phonepe', 'gpay', 'upi', 'bank', 'ybl', 'ibl', 'okaxis', 'okhdfcbank', 'okicici'])]
    
    # URLs and phishing links
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+|bit\.ly/[^\s]+', conversation_text)
    
    # Phone numbers (Indian format)
    phone_numbers = re.findall(r'\b[6-9]\d{9}\b', conversation_text)
    
    return {
        'bank_accounts': list(set(bank_accounts)),
        'upi_ids': list(set(upi_ids)),
        'phishing_links': list(set(urls)),
        'phone_numbers': list(set(phone_numbers))
    }


def get_scam_type(message):
    """Identify the type of scam"""
    message_lower = message.lower()
    
    if any(word in message_lower for word in ['lottery', 'won', 'prize', 'winner', 'congratulations']):
        return 'lottery_fraud'
    elif any(word in message_lower for word in ['bank', 'account', 'suspended', 'blocked']):
        return 'banking_fraud'
    elif any(word in message_lower for word in ['otp', 'verify', 'code', 'confirm']):
        return 'otp_fraud'
    elif any(word in message_lower for word in ['refund', 'tax', 'payment']):
        return 'refund_fraud'
    elif any(word in message_lower for word in ['job', 'earn', 'work from home']):
        return 'job_fraud'
    elif any(word in message_lower for word in ['investment', 'profit', 'returns', 'trading']):
        return 'investment_fraud'
    else:
        return 'unknown'


def chat_with_scammer(scammer_message, conversation_history):
    """Generate AI response to scammer using OpenAI"""
    
    system_prompt = """You are roleplaying as a believable target for scammers. Your goal:

1. Act interested and curious (but not too eager)
2. Ask natural questions to extract information like:
   - Bank account details
   - UPI IDs  
   - Website links
   - Phone numbers
3. Seem slightly naive but realistic
4. Keep responses SHORT (1-2 sentences maximum)
5. Show appropriate emotions: excitement, concern, or confusion
6. NEVER reveal you know it's a scam
7. Build trust gradually before asking for sensitive details

Example good responses:
- "Wow really? How do I claim this?"
- "That sounds urgent! What should I do?"
- "I'm interested but a bit confused, can you explain more?"
- "Where should I send my details?"
- "What's your bank account or UPI ID?"

Be natural and human-like! Stay in character."""

    # Build message history for OpenAI
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add last 6 messages for context (to keep token usage low)
    for turn in conversation_history[-6:]:
        role = "assistant" if turn['speaker'] == 'agent' else "user"
        messages.append({
            "role": role,
            "content": turn['message']
        })
    
    # Add current scammer message
    messages.append({
        "role": "user",
        "content": scammer_message
    })
    
    try:
        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Fast and cheap model
            messages=messages,
            max_tokens=100,
            temperature=0.8  # More creative/natural responses
        )
        
        return response.choices[0].message.content.strip()
    
    except Exception as e:
        print(f"OpenAI API Error: {e}")
        # Fallback responses if API fails
        fallback_responses = [
            "Really? Tell me more about this!",
            "I'm interested. What do I need to do?",
            "How does this work exactly?",
            "That sounds great! What's the next step?",
            "Can you send me the link or your contact details?"
        ]
        import random
        return random.choice(fallback_responses)


@app.route('/honeypot', methods=['POST'])
def honeypot():
    """Main endpoint for scam detection"""
    
    # Check authentication
    if not check_api_key(request):
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Invalid or missing API key'
        }), 401
    
    # Validate request
    data = request.json
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    if 'message' not in data:
        return jsonify({'error': 'Missing required field: message'}), 400
    
    message = data['message']
    session_id = data.get('session_id', f'session_{datetime.now().timestamp()}')
    
    # Initialize conversation for this session
    if session_id not in conversations:
        conversations[session_id] = []
    
    # Detect if it's a scam
    is_scam, confidence, matched_keywords = detect_scam(message)
    
    # Add scammer's message to conversation history
    conversations[session_id].append({
        'speaker': 'scammer',
        'message': message,
        'timestamp': datetime.now().isoformat()
    })
    
    # Generate AI agent response
    try:
        agent_response = chat_with_scammer(message, conversations[session_id])
    except Exception as e:
        print(f"Error generating response: {e}")
        agent_response = "I'm interested, please tell me more."
    
    # Add agent's response to conversation history
    conversations[session_id].append({
        'speaker': 'agent',
        'message': agent_response,
        'timestamp': datetime.now().isoformat()
    })
    
    # Extract intelligence from entire conversation
    full_text = ' '.join([turn['message'] for turn in conversations[session_id]])
    intelligence = extract_intelligence(full_text)
    
    # Build final response
    response_data = {
        'is_scam': is_scam,
        'confidence_score': confidence,
        'extracted_intelligence': {
            'bank_accounts': intelligence['bank_accounts'],
            'upi_ids': intelligence['upi_ids'],
            'phishing_links': intelligence['phishing_links'],
            'scam_type': get_scam_type(message),
            'additional_info': {
                'matched_scam_keywords': matched_keywords[:5],  # Top 5
                'total_messages': len(conversations[session_id]),
                'phone_numbers': intelligence['phone_numbers']
            }
        },
        'conversation_log': conversations[session_id],
        'agent_response': agent_response
    }
    
    return jsonify(response_data), 200


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_sessions': len(conversations)
    }), 200


@app.route('/', methods=['GET'])
def home():
    """Home endpoint"""
    return jsonify({
        'service': 'Scam Honeypot API',
        'version': '1.0',
        'endpoints': {
            'POST /honeypot': 'Main scam detection endpoint',
            'GET /health': 'Health check'
        }
    }), 200


if __name__ == '__main__':
    # Check if API key is loaded
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  WARNING: OPENAI_API_KEY not found in .env file!")
        print("Please create a .env file with your OpenAI API key")
    else:
        print("✅ OpenAI API key loaded successfully!")
    
    port = int(os.getenv('PORT', 5000))
    print(f"🚀 Starting server on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)