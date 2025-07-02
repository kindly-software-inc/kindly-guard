// Icon generator for KindlyGuard extension
// Creates SVG-based icons in different sizes

const fs = require('fs');
const path = require('path');

const shieldSvg = `
<svg width="128" height="128" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="128" height="128" rx="24" fill="url(#gradient)"/>
  <path d="M64 20L32 40V64C32 88 45.36 109.92 62 117.28C62.7 117.52 63.32 117.52 64 117.28C80.64 109.92 96 88 96 64V40L64 20Z" 
        fill="white" stroke="white" stroke-width="4"/>
  <path d="M52 64L60 72L76 56" stroke="url(#gradient)" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>
  <defs>
    <linearGradient id="gradient" x1="0" y1="0" x2="128" y2="128" gradientUnits="userSpaceOnUse">
      <stop stop-color="#7C3AED"/>
      <stop offset="1" stop-color="#6B46C1"/>
    </linearGradient>
  </defs>
</svg>
`;

// Helper to convert SVG to data URL
function svgToDataUrl(svg) {
  const base64 = Buffer.from(svg).toString('base64');
  return `data:image/svg+xml;base64,${base64}`;
}

// Generate HTML with canvas for each size
const sizes = [16, 32, 48, 128];
const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
  <title>Generate Icons</title>
</head>
<body>
  <h1>KindlyGuard Extension Icons</h1>
  <p>Right-click each icon and save as PNG:</p>
  ${sizes.map(size => `
    <div style="margin: 20px;">
      <h3>${size}x${size}</h3>
      <canvas id="canvas-${size}" width="${size}" height="${size}" style="border: 1px solid #ccc;"></canvas>
    </div>
  `).join('')}
  
  <script>
    const svg = \`${shieldSvg}\`;
    const sizes = [${sizes.join(', ')}];
    
    sizes.forEach(size => {
      const canvas = document.getElementById(\`canvas-\${size}\`);
      const ctx = canvas.getContext('2d');
      
      const img = new Image();
      img.onload = function() {
        ctx.drawImage(img, 0, 0, size, size);
      };
      img.src = '${svgToDataUrl(shieldSvg)}';
    });
  </script>
</body>
</html>
`;

// Write the HTML file
const outputPath = path.join(__dirname, '../../assets/generate-icons.html');
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, htmlTemplate);

console.log(`Icon generator created at: ${outputPath}`);
console.log('Open this file in a browser and save each icon as PNG');

// Also create a simple SVG icon as fallback
fs.writeFileSync(path.join(__dirname, '../../assets/icon.svg'), shieldSvg);
console.log('SVG icon saved to assets/icon.svg');