# OCR Service - ID Card Scanner

## Overview
This service uses Tesseract.js to extract identity numbers from Tunisian ID cards.

## Endpoints

### 1. Scan ID Card
**POST** `/users/scan-id-card`

Extracts the identity number from an uploaded ID card image.

**Request:**
- Content-Type: `multipart/form-data`
- Field name: `image`
- Supported formats: JPEG, PNG, WEBP

**Example using cURL:**
```bash
curl -X POST http://localhost:3000/users/scan-id-card \
  -F "image=@/path/to/id-card.jpg"
```

**Example using Postman:**
1. Select POST method
2. Enter URL: `http://localhost:3000/users/scan-id-card`
3. Go to Body tab
4. Select "form-data"
5. Add key "image" with type "File"
6. Upload your ID card image

**Response:**
```json
{
  "success": true,
  "identityNumber": "09352146",
  "message": "Identity number extracted successfully"
}
```

### 2. Debug Endpoint (Extract All Text)
**POST** `/users/scan-id-card/debug`

Extracts all text from the ID card for debugging purposes.

**Request:**
Same as above

**Response:**
```json
{
  "success": true,
  "extractedText": "الجمهورية التونسية\nبطاقة التعرف الوطنية\n09352146\n...",
  "message": "Text extracted successfully"
}
```

## Features
- Supports Arabic and English text recognition
- Extracts 8-digit Tunisian identity numbers
- Validates image file types
- Provides detailed error messages

## Error Handling
- Returns `400 Bad Request` if no file is uploaded
- Returns `400 Bad Request` if file type is not supported
- Returns `400 Bad Request` if identity number cannot be extracted

## Tips for Best Results
1. Ensure the ID card image is clear and well-lit
2. Avoid shadows or glare on the card
3. The image should be in focus
4. Higher resolution images generally work better
