/**
 * Style constants for KindlyGuard UI components
 * Designed to match Claude Code's dark theme
 */

export const COLORS = {
  // Background colors
  backgroundPrimary: 'rgba(30, 30, 30, 0.95)',
  backgroundSecondary: 'rgba(40, 40, 40, 0.95)',
  backgroundHover: 'rgba(50, 50, 50, 0.95)',
  
  // Text colors
  textPrimary: '#ffffff',
  textSecondary: '#999999',
  textMuted: '#666666',
  
  // Status colors
  statusConnected: '#00ff00',
  statusDisconnected: '#ff6b6b',
  statusWarning: '#ffa500',
  
  // Threat severity colors
  threatCritical: '#ff0000',
  threatHigh: '#ff6b6b',
  threatMedium: '#ffa500',
  threatLow: '#4a9eff',
  
  // Border and accent
  border: 'rgba(255, 255, 255, 0.1)',
  borderHover: 'rgba(255, 255, 255, 0.2)',
  accent: '#4a9eff',
  accentHover: '#6bb1ff'
};

export const TYPOGRAPHY = {
  fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  fontSizeSmall: '11px',
  fontSizeBase: '12px',
  fontSizeLarge: '14px',
  fontWeightNormal: 400,
  fontWeightMedium: 500,
  fontWeightBold: 600
};

export const SPACING = {
  xs: '4px',
  sm: '8px',
  md: '12px',
  lg: '16px',
  xl: '24px'
};

export const ANIMATION = {
  duration: '200ms',
  easing: 'cubic-bezier(0.4, 0, 0.2, 1)'
};

export const WIDGET_STYLES = `
  .shield-widget {
    background: ${COLORS.backgroundPrimary};
    border: 1px solid ${COLORS.border};
    border-radius: 8px;
    padding: ${SPACING.md};
    font-family: ${TYPOGRAPHY.fontFamily};
    font-size: ${TYPOGRAPHY.fontSizeBase};
    color: ${COLORS.textPrimary};
    transition: all ${ANIMATION.duration} ${ANIMATION.easing};
  }
  
  .shield-widget:hover {
    background: ${COLORS.backgroundSecondary};
    border-color: ${COLORS.borderHover};
  }
  
  .threat-notification {
    display: flex;
    align-items: center;
    padding: ${SPACING.sm} ${SPACING.md};
    background: ${COLORS.backgroundSecondary};
    border-radius: 6px;
    margin-bottom: ${SPACING.sm};
  }
  
  .threat-critical { border-left: 3px solid ${COLORS.threatCritical}; }
  .threat-high { border-left: 3px solid ${COLORS.threatHigh}; }
  .threat-medium { border-left: 3px solid ${COLORS.threatMedium}; }
  .threat-low { border-left: 3px solid ${COLORS.threatLow}; }
`;