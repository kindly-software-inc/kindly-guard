// Shield Glow Shader - WebGPU Shader Language (WGSL)
// For enhanced shield visualization with energy field effects

// Vertex shader
struct VertexInput {
    @location(0) position: vec3<f32>,
    @location(1) uv: vec2<f32>,
}

struct VertexOutput {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
    @location(1) world_pos: vec3<f32>,
}

struct Uniforms {
    time: f32,
    shield_color: vec3<f32>,
    glow_intensity: f32,
    pulse_speed: f32,
    energy_level: f32,
}

@group(0) @binding(0)
var<uniform> uniforms: Uniforms;

@vertex
fn vs_main(input: VertexInput) -> VertexOutput {
    var output: VertexOutput;
    output.position = vec4<f32>(input.position, 1.0);
    output.uv = input.uv;
    output.world_pos = input.position;
    return output;
}

// Fragment shader
@fragment
fn fs_main(input: VertexOutput) -> @location(0) vec4<f32> {
    let center = vec2<f32>(0.5, 0.5);
    let dist = distance(input.uv, center);
    
    // Shield shape (approximated as a rounded rectangle with top narrowing)
    let shield_shape = shield_sdf(input.uv);
    
    // Energy field calculation
    let energy_wave = sin(uniforms.time * uniforms.pulse_speed + dist * 10.0) * 0.5 + 0.5;
    let energy_intensity = uniforms.energy_level * energy_wave;
    
    // Glow effect
    let glow = calculate_glow(shield_shape, uniforms.glow_intensity);
    
    // Plasma effect for enhanced mode
    let plasma = plasma_effect(input.uv, uniforms.time);
    
    // Combine colors
    var color = uniforms.shield_color;
    
    // Add energy field
    color = mix(color, vec3<f32>(0.925, 0.706, 1.0), energy_intensity * 0.3);
    
    // Add plasma effect
    color = mix(color, plasma, 0.2 * uniforms.energy_level);
    
    // Apply glow
    let alpha = smoothstep(0.0, 1.0, glow);
    
    return vec4<f32>(color * (1.0 + glow * 0.5), alpha);
}

// Shield signed distance function
fn shield_sdf(uv: vec2<f32>) -> f32 {
    // Transform UV to centered coordinates
    let p = uv - vec2<f32>(0.5, 0.5);
    
    // Shield shape parameters
    let width = 0.3;
    let height = 0.4;
    let top_narrow = 0.8; // How much the top narrows
    
    // Calculate shield outline
    let y_factor = smoothstep(-height, height, p.y);
    let current_width = mix(width, width * top_narrow, y_factor);
    
    // Distance to shield edge
    let d_x = abs(p.x) - current_width;
    let d_y = abs(p.y) - height;
    
    // Combine distances
    let d = max(d_x, d_y);
    
    // Round the bottom
    if (p.y < -height * 0.7) {
        let bottom_center = vec2<f32>(0.0, -height);
        let bottom_dist = distance(p, bottom_center);
        return min(d, bottom_dist - width * 0.5);
    }
    
    return d;
}

// Calculate glow intensity based on distance from shield edge
fn calculate_glow(dist: f32, intensity: f32) -> f32 {
    // Multiple glow layers for depth
    let glow1 = exp(-abs(dist) * 3.0) * intensity;
    let glow2 = exp(-abs(dist) * 6.0) * intensity * 0.5;
    let glow3 = exp(-abs(dist) * 12.0) * intensity * 0.25;
    
    return glow1 + glow2 + glow3;
}

// Plasma effect for enhanced visualization
fn plasma_effect(uv: vec2<f32>, time: f32) -> vec3<f32> {
    var color = vec3<f32>(0.0);
    
    // Create moving plasma waves
    for (var i = 0; i < 4; i = i + 1) {
        let fi = f32(i);
        let a = fi * 0.5 + time * 0.1;
        let b = fi * 0.3 + time * 0.15;
        
        color = color + 0.25 * cos(
            vec3<f32>(0.0, 2.0, 4.0) + 
            6.28318 * (
                uv.x * cos(a) + uv.y * sin(b) + 
                sin(time * 0.3 + fi)
            )
        );
    }
    
    // Convert to purple-pink palette
    color = vec3<f32>(
        color.r * 0.8 + 0.2,
        color.g * 0.4 + 0.1,
        color.b * 0.9 + 0.1
    );
    
    return clamp(color, vec3<f32>(0.0), vec3<f32>(1.0));
}

// Noise function for additional effects
fn noise(p: vec2<f32>) -> f32 {
    let k = vec2<f32>(0.366025404, 0.211324865); // (sqrt(3)/2, (sqrt(3)-1)/2)
    let i = floor(p + dot(p, k));
    let a = p - i + dot(i, vec2<f32>(0.211324865));
    let o = select(vec2<f32>(0.0, 1.0), vec2<f32>(1.0, 0.0), a.x > a.y);
    let b = a - o + vec2<f32>(0.211324865);
    let c = a - 1.0 + 2.0 * vec2<f32>(0.211324865);
    let h = max(0.5 - vec3<f32>(dot(a, a), dot(b, b), dot(c, c)), vec3<f32>(0.0));
    let h3 = h * h * h;
    let n = h3.x * dot(a, hash2(i)) + 
            h3.y * dot(b, hash2(i + o)) + 
            h3.z * dot(c, hash2(i + 1.0));
    return n * 70.0;
}

// Hash function for noise
fn hash2(p: vec2<f32>) -> vec2<f32> {
    let k = vec2<f32>(0.3183099, 0.3678794);
    let p2 = p * k + k.yx;
    return -1.0 + 2.0 * fract(16.0 * k * fract(p2.x * p2.y * (p2.x + p2.y)));
}