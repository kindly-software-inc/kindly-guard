// Shield Glow Shader - WebGL 2.0 GLSL
// Fallback shader for systems without WebGPU support

// Vertex Shader
#ifdef VERTEX_SHADER
attribute vec3 a_position;
attribute vec2 a_uv;

varying vec2 v_uv;
varying vec3 v_world_pos;

void main() {
    gl_Position = vec4(a_position, 1.0);
    v_uv = a_uv;
    v_world_pos = a_position;
}
#endif

// Fragment Shader
#ifdef FRAGMENT_SHADER
precision highp float;

uniform float u_time;
uniform vec3 u_shield_color;
uniform float u_glow_intensity;
uniform float u_pulse_speed;
uniform float u_energy_level;

varying vec2 v_uv;
varying vec3 v_world_pos;

// Shield signed distance function
float shieldSDF(vec2 uv) {
    vec2 p = uv - vec2(0.5, 0.5);
    
    float width = 0.3;
    float height = 0.4;
    float topNarrow = 0.8;
    
    float yFactor = smoothstep(-height, height, p.y);
    float currentWidth = mix(width, width * topNarrow, yFactor);
    
    float dX = abs(p.x) - currentWidth;
    float dY = abs(p.y) - height;
    
    float d = max(dX, dY);
    
    // Round the bottom
    if (p.y < -height * 0.7) {
        vec2 bottomCenter = vec2(0.0, -height);
        float bottomDist = distance(p, bottomCenter);
        return min(d, bottomDist - width * 0.5);
    }
    
    return d;
}

// Calculate glow intensity
float calculateGlow(float dist, float intensity) {
    float glow1 = exp(-abs(dist) * 3.0) * intensity;
    float glow2 = exp(-abs(dist) * 6.0) * intensity * 0.5;
    float glow3 = exp(-abs(dist) * 12.0) * intensity * 0.25;
    
    return glow1 + glow2 + glow3;
}

// Simple noise function
float noise(vec2 p) {
    vec2 k = vec2(0.366025404, 0.211324865);
    vec2 i = floor(p + dot(p, k));
    vec2 a = p - i + dot(i, vec2(0.211324865));
    vec2 o = a.x > a.y ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
    vec2 b = a - o + vec2(0.211324865);
    vec2 c = a - 1.0 + 2.0 * vec2(0.211324865);
    vec3 h = max(0.5 - vec3(dot(a, a), dot(b, b), dot(c, c)), 0.0);
    vec3 h3 = h * h * h;
    
    // Simplified hash
    float n1 = sin(dot(i, vec2(12.9898, 78.233))) * 43758.5453;
    float n2 = sin(dot(i + o, vec2(12.9898, 78.233))) * 43758.5453;
    float n3 = sin(dot(i + 1.0, vec2(12.9898, 78.233))) * 43758.5453;
    
    return 70.0 * dot(h3, vec3(n1, n2, n3));
}

// Plasma effect
vec3 plasmaEffect(vec2 uv, float time) {
    vec3 color = vec3(0.0);
    
    for (int i = 0; i < 4; i++) {
        float fi = float(i);
        float a = fi * 0.5 + time * 0.1;
        float b = fi * 0.3 + time * 0.15;
        
        color += 0.25 * cos(
            vec3(0.0, 2.0, 4.0) + 
            6.28318 * (
                uv.x * cos(a) + uv.y * sin(b) + 
                sin(time * 0.3 + fi)
            )
        );
    }
    
    // Convert to purple-pink palette
    color = vec3(
        color.r * 0.8 + 0.2,
        color.g * 0.4 + 0.1,
        color.b * 0.9 + 0.1
    );
    
    return clamp(color, 0.0, 1.0);
}

void main() {
    vec2 center = vec2(0.5, 0.5);
    float dist = distance(v_uv, center);
    
    // Shield shape
    float shieldShape = shieldSDF(v_uv);
    
    // Energy field
    float energyWave = sin(u_time * u_pulse_speed + dist * 10.0) * 0.5 + 0.5;
    float energyIntensity = u_energy_level * energyWave;
    
    // Glow effect
    float glow = calculateGlow(shieldShape, u_glow_intensity);
    
    // Plasma effect for enhanced mode
    vec3 plasma = plasmaEffect(v_uv, u_time);
    
    // Combine colors
    vec3 color = u_shield_color;
    
    // Add energy field
    color = mix(color, vec3(0.925, 0.706, 1.0), energyIntensity * 0.3);
    
    // Add plasma effect
    color = mix(color, plasma, 0.2 * u_energy_level);
    
    // Apply glow
    float alpha = smoothstep(0.0, 1.0, glow);
    
    // Add shield interior
    if (shieldShape < 0.0) {
        alpha = 1.0;
        color *= 1.2; // Brighten interior slightly
    }
    
    gl_FragColor = vec4(color * (1.0 + glow * 0.5), alpha);
}
#endif