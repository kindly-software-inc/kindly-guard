# KindlyGuard Shield Visual Assets

This directory contains all visual components for the KindlyGuard security shield display system, including both standard (blue theme) and enhanced (purple theme) versions.

## Directory Structure

```
assets/
├── animations/     # CSS animations for shield effects
├── css/           # Stylesheets for widgets and visualizations
├── icons/         # System tray icons for all platforms
├── js/            # JavaScript for widget interactivity
├── shaders/       # WebGL/WebGPU shaders for enhanced effects
├── svg/           # Shield vector graphics
└── templates/     # HTML templates for widgets
```

## Shield Variants

### 1. Standard Shield (Blue Theme)
- **File**: `svg/shield-standard.svg`
- **Colors**: Blue gradient (#4A90E2 to #2C5AA0)
- **Features**: Static design with checkmark, subtle glow
- **Use Case**: Default protection mode

### 2. Enhanced Shield (Purple Theme)
- **File**: `svg/shield-enhanced.svg`
- **Colors**: Purple gradient (#9B59B6 to #6C3483)
- **Features**: Animated particles, energy field, lightning bolt
- **Use Case**: Enhanced protection mode with advanced features

### 3. Threat States
- **shield-inactive.svg**: Gray shield for disabled state
- **shield-threat-detected.svg**: Red alert shield for active threats

## System Tray Icons

Platform-specific icons are provided in the `icons/` directory:

### States
- `tray-protected.svg`: Green outline (normal protection)
- `tray-warning.svg`: Yellow with exclamation (warnings detected)
- `tray-critical.svg`: Red with X mark (critical threats)
- `tray-enhanced.svg`: Purple with glow (enhanced mode active)

### Platform Conversion
Use the provided `icons/convert-icons.sh` script to generate platform-specific formats:
```bash
cd icons
./convert-icons.sh
```

This creates:
- **Windows**: `.ico` files (16, 32, 48, 256px)
- **macOS**: `.png` files with @2x Retina variants
- **Linux**: `.png` files in standard sizes

## Animations

### Shield Pulse (`animations/shield-pulse.css`)
Professional CSS animations for shield states:
- **Standard breathing**: Subtle scale animation
- **Enhanced pulse**: Dynamic glow with energy effects
- **Threat alert**: Rapid flash for threat detection
- **Energy particles**: Floating particle effects for enhanced mode

### Usage
```html
<link rel="stylesheet" href="assets/animations/shield-pulse.css">
<div class="shield-container">
    <img src="assets/svg/shield-standard.svg" class="shield-standard active">
</div>
```

## WebGL Shaders

### Enhanced Glow Effect (`shaders/shield-glow.wgsl` / `.glsl`)
Advanced shader effects for enhanced mode visualization:
- **Energy field**: Pulsing plasma effect
- **Dynamic glow**: Distance-based glow intensity
- **Noise patterns**: Procedural energy visualization

Includes both WebGPU (WGSL) and WebGL 2.0 (GLSL) versions for compatibility.

## Claude Code Widget

### Widget Structure (`templates/claude-widget.html`)
Compact, expandable shield widget designed for Claude Code integration:
- **Collapsed**: 64x64px floating shield with threat counter
- **Expanded**: 320px wide panel with full metrics
- **Responsive**: Adapts to screen size
- **Accessible**: Full keyboard navigation support

### Widget Styles (`css/widget.css`)
Professional dark theme with:
- Smooth transitions between states
- Enhanced mode color shifts
- Reduced motion support
- High contrast accessibility

## Threat Visualization

### Components (`templates/threat-visualization.html`)
Advanced visualization dashboard for enhanced mode:
- **Threat Map**: Real-time radar display
- **Distribution Charts**: Threat type breakdown
- **Neural Network**: Pattern recognition visualization
- **Heatmap**: Attack pattern intensity grid
- **Live Stream**: Real-time threat feed

## Integration Example

```javascript
// Initialize shield widget
const shield = new ShieldWidget({
    enhanced: true,              // Enable enhanced mode
    container: '#shield-widget', // Mount point
    theme: 'purple',            // or 'blue' for standard
    animations: true            // Enable animations
});

// Update threat count
shield.updateThreats(5);

// Switch modes
shield.toggleEnhancedMode();
```

## Design Guidelines

### Color Palette
- **Standard Mode**: Professional blue tones
- **Enhanced Mode**: Premium purple gradients
- **Threat States**: Traffic light system (green/yellow/red)
- **Dark UI**: #1a1a1a background with high contrast

### Animation Performance
- All animations use GPU acceleration
- Reduced motion media query support
- 60fps target for smooth effects
- Fallbacks for older browsers

### Accessibility
- WCAG 2.1 AA compliance
- Keyboard navigation support
- Screen reader friendly
- High contrast mode compatible

## Browser Support
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- WebGPU: Chrome 113+ (with fallback to WebGL)

## Performance Considerations
- SVGs are optimized for small file size
- CSS animations use `transform` and `opacity` only
- WebGL shaders include LOD support
- Lazy loading for visualization components

## Future Enhancements
- [ ] 3D shield model for AR/VR
- [ ] Haptic feedback integration
- [ ] Voice alert system
- [ ] Mobile app assets
- [ ] Custom theming API