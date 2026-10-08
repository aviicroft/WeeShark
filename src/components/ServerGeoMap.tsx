import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  MapPin,
  Navigation,
  Globe,
  Maximize2,
  Minimize2,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Copy,
  Check,
  Server,
  Clock,
  Shield,
  Radio,
} from 'lucide-react';

export interface GeoData {
  ip?: string;
  success?: boolean;
  city?: string;
  region?: string;
  country?: string;
  country_code?: string;
  continent?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  org?: string;
  asn?: string;
  timezone?: string;
  postal?: string;
  is_private?: boolean;
}

interface ServerGeoMapProps {
  geo?: GeoData;
  hostname: string;
  ip: string;
  className?: string;
  height?: string;
  showDetailsPanel?: boolean;
}

// Convert 2-letter country code to Unicode Flag Emoji
function getFlagEmoji(countryCode?: string): string {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// Format coordinates to user-friendly DMS or degrees
function formatCoords(lat?: number, lng?: number): string {
  if (typeof lat !== 'number' || typeof lng !== 'number' || (lat === 0 && lng === 0)) {
    return 'Coordinates Unavailable';
  }
  const latDir = lat >= 0 ? 'N' : 'S';
  const lngDir = lng >= 0 ? 'E' : 'W';
  return `${Math.abs(lat).toFixed(4)}° ${latDir}, ${Math.abs(lng).toFixed(4)}° ${lngDir}`;
}

export const ServerGeoMap: React.FC<ServerGeoMapProps> = ({
  geo,
  hostname,
  ip,
  className = '',
  height = '360px',
  showDetailsPanel = true,
}) => {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const markerRef = useRef<L.Marker | null>(null);

  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [localTime, setLocalTime] = useState<string>('');

  // Dynamically load Mapbox token from environment or config endpoint - NO hardcoded secrets
  const [mapboxToken, setMapboxToken] = useState<string>(
    () =>
      ((import.meta as any).env?.VITE_MAPBOX_TOKEN?.trim() ||
        (import.meta as any).env?.MAPBOX_TOKEN?.trim() ||
        '')
  );

  useEffect(() => {
    if (!mapboxToken) {
      fetch('/api/config')
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data?.mapbox_token) {
            setMapboxToken(data.mapbox_token.trim());
          }
        })
        .catch(() => {});
    }
  }, [mapboxToken]);

  const lat = geo?.latitude ?? 0;
  const lng = geo?.longitude ?? 0;
  const hasValidCoords = typeof lat === 'number' && typeof lng === 'number' && (lat !== 0 || lng !== 0);

  // Calculate local time for server timezone
  useEffect(() => {
    if (geo?.timezone) {
      try {
        const updateTime = () => {
          const now = new Date();
          const formatter = new Intl.DateTimeFormat('en-US', {
            timeZone: geo.timezone,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true,
            timeZoneName: 'short',
          });
          setLocalTime(formatter.format(now));
        };
        updateTime();
        const timer = setInterval(updateTime, 1000);
        return () => clearInterval(timer);
      } catch {
        setLocalTime('');
      }
    } else {
      setLocalTime('');
    }
  }, [geo?.timezone]);

  // Initialize or update Leaflet Map
  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (!hasValidCoords) {
      // Clean up existing map if coordinates are not available
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
      return;
    }

    const container = mapContainerRef.current;

    // Check if map already created
    if (!mapInstanceRef.current) {
      const map = L.map(container, {
        center: [lat, lng],
        zoom: 6,
        zoomControl: false,
        attributionControl: false,
        scrollWheelZoom: true,
      });

      // Attribution control: displays "Mapbox · OpenStreetMap | © Mapbox © OpenStreetMap"
      L.control
        .attribution({
          position: 'bottomright',
          prefix:
            '<a href="https://www.mapbox.com/about/maps/" target="_blank" rel="noopener noreferrer">Mapbox</a> · <a href="https://www.openstreetmap.org/about/" target="_blank" rel="noopener noreferrer">OpenStreetMap</a>',
        })
        .addTo(map);

      mapInstanceRef.current = map;
    } else {
      // Map exists, pan to updated coordinates
      mapInstanceRef.current.setView([lat, lng], 7, { animate: true });
    }

    const map = mapInstanceRef.current;

    // Dynamically manage tile layer using Mapbox Dark-v11 tiles
    if (tileLayerRef.current) {
      tileLayerRef.current.remove();
      tileLayerRef.current = null;
    }

    const layer = mapboxToken
      ? L.tileLayer(
          `https://api.mapbox.com/styles/v1/mapbox/dark-v11/tiles/{z}/{x}/{y}?access_token=${mapboxToken}`,
          {
            tileSize: 512,
            zoomOffset: -1,
            maxZoom: 19,
            attribution: '© Mapbox © OpenStreetMap',
          }
        )
      : L.tileLayer(
          'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
          {
            subdomains: 'abcd',
            maxZoom: 19,
            attribution: '© Mapbox © OpenStreetMap',
          }
        );

    layer.addTo(map);
    tileLayerRef.current = layer;

    // Remove prior marker
    if (markerRef.current) {
      markerRef.current.remove();
      markerRef.current = null;
    }

    // Custom Glowing Radar Marker Icon
    const customIcon = L.divIcon({
      className: 'custom-server-radar-marker',
      html: `
        <div style="position: relative; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;">
          <div style="position: absolute; width: 36px; height: 36px; border-radius: 50%; background: rgba(6, 182, 212, 0.25); animation: leafletSonar 2s cubic-bezier(0, 0.2, 0.8, 1) infinite;"></div>
          <div style="position: absolute; width: 22px; height: 22px; border-radius: 50%; background: rgba(6, 182, 212, 0.4); animation: leafletSonar 2s cubic-bezier(0, 0.2, 0.8, 1) 0.5s infinite;"></div>
          <div style="position: relative; width: 14px; height: 14px; border-radius: 50%; background: #06b6d4; border: 2.5px solid #ffffff; box-shadow: 0 0 12px #06b6d4, 0 0 20px rgba(6,182,212,0.8);"></div>
        </div>
      `,
      iconSize: [36, 36],
      iconAnchor: [18, 18],
      popupAnchor: [0, -20],
    });

    const marker = L.marker([lat, lng], { icon: customIcon }).addTo(map);

    // Popup content with rich styling
    const popupContent = `
      <div style="font-family: 'Plus Jakarta Sans', system-ui, sans-serif; min-width: 200px; padding: 4px 2px; color: #f1f5f9;">
        <div style="font-size: 10px; font-family: monospace; color: #06b6d4; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">
          SERVER HOST LOCATION
        </div>
        <div style="font-size: 13px; font-weight: 700; color: #ffffff; margin-bottom: 4px;">
          ${geo?.city ? `${geo.city}, ` : ''}${geo?.country || 'Server Node'}
        </div>
        <div style="font-size: 11px; font-family: monospace; color: #94a3b8; margin-bottom: 6px; padding-bottom: 6px; border-bottom: 1px solid rgba(148, 163, 184, 0.15);">
          IP: <strong style="color: #38bdf8;">${ip || geo?.ip}</strong>
        </div>
        <div style="font-size: 11px; color: #cbd5e1; display: flex; flex-direction: column; gap: 3px;">
          <div><span style="color: #64748b;">ISP:</span> <strong>${geo?.isp || 'Cloud Host'}</strong></div>
          ${geo?.asn ? `<div><span style="color: #64748b;">ASN:</span> <code style="color: #22d3ee;">${geo.asn}</code></div>` : ''}
          <div><span style="color: #64748b;">GPS:</span> <span style="font-family: monospace; font-size: 10px;">${lat.toFixed(4)}, ${lng.toFixed(4)}</span></div>
        </div>
      </div>
    `;

    marker.bindPopup(popupContent, {
      className: 'dark-cyber-popup',
      closeButton: false,
    });

    markerRef.current = marker;

    // Automatically trigger resize recalculation
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 200);

    return () => {
      clearTimeout(timer);
    };
  }, [lat, lng, hasValidCoords, ip, geo, hostname, mapboxToken]);

  // Clean up on component unmount
  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Handle container resize when expanding
  useEffect(() => {
    if (mapInstanceRef.current) {
      setTimeout(() => {
        mapInstanceRef.current?.invalidateSize();
      }, 150);
    }
  }, [isExpanded]);

  const handleCopyIp = () => {
    if (ip) {
      navigator.clipboard.writeText(ip);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleZoomIn = () => {
    mapInstanceRef.current?.zoomIn();
  };

  const handleZoomOut = () => {
    mapInstanceRef.current?.zoomOut();
  };

  const handleResetCenter = () => {
    if (hasValidCoords && mapInstanceRef.current) {
      mapInstanceRef.current.setView([lat, lng], 7, { animate: true });
      markerRef.current?.openPopup();
    }
  };

  return (
    <div
      className={`relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900 shadow-xl transition-all duration-300 ${className}`}
    >
      <style>{`
        @keyframes leafletSonar {
          0% { transform: scale(0.6); opacity: 0.9; }
          70% { transform: scale(2.0); opacity: 0; }
          100% { transform: scale(2.2); opacity: 0; }
        }
        .dark-cyber-popup .leaflet-popup-content-wrapper {
          background: #0f172a !important;
          border: 1px solid rgba(6, 182, 212, 0.3) !important;
          border-radius: 10px !important;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.7), 0 0 15px rgba(6, 182, 212, 0.2) !important;
          padding: 4px !important;
        }
        .dark-cyber-popup .leaflet-popup-tip {
          background: #0f172a !important;
          border: 1px solid rgba(6, 182, 212, 0.3) !important;
        }
        .leaflet-container {
          background: #0b0f19 !important;
        }
        .leaflet-control-attribution {
          background: rgba(11, 15, 25, 0.85) !important;
          backdrop-filter: blur(4px) !important;
          border: 1px solid rgba(51, 65, 85, 0.5) !important;
          border-radius: 4px !important;
          color: #94a3b8 !important;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
          font-size: 9.5px !important;
          padding: 2px 6px !important;
          margin: 0 4px 4px 0 !important;
        }
        .leaflet-control-attribution a {
          color: #38bdf8 !important;
          text-decoration: none !important;
        }
        .leaflet-control-attribution a:hover {
          text-decoration: underline !important;
        }
      `}</style>

      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-950/70 px-4 py-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/60 text-cyan-400 border border-cyan-500/30">
            <Radio className="h-4 w-4 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-white">
                Server Geolocation & Physical Infrastructure
              </h4>
              <span className="flex items-center gap-1 rounded bg-emerald-950/70 border border-emerald-500/30 px-1.5 py-0.5 text-[10px] font-bold font-mono text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                LIVE NODE
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Datacenter location resolved for <span className="text-cyan-300">{hostname}</span>
            </p>
          </div>
        </div>

        {/* IP Badge with Copy Button */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-lg bg-slate-900 border border-slate-800 px-3 py-1 font-mono text-xs">
            <span className="text-[10px] text-slate-500 uppercase">IP:</span>
            <span className="font-bold text-white tracking-wide">{ip || geo?.ip || 'Resolving...'}</span>
            <button
              onClick={handleCopyIp}
              title="Copy IP Address"
              className="ml-1 text-slate-400 hover:text-cyan-300 transition-colors"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            title={isExpanded ? 'Collapse Map' : 'Expand Map'}
            className="rounded-lg bg-slate-800/80 hover:bg-slate-700 p-1.5 text-slate-300 hover:text-white transition-colors"
          >
            {isExpanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Map Body Area */}
      <div className="relative w-full" style={{ height: isExpanded ? '520px' : height }}>
        {hasValidCoords ? (
          <>
            {/* The Actual Leaflet Map Canvas */}
            <div ref={mapContainerRef} className="h-full w-full z-0" />

            {/* Floating Cyber HUD Overlay (Top-Left) */}
            <div className="absolute top-3 left-3 z-[400] flex flex-col gap-1.5 pointer-events-none">
              {/* Location HUD Badge */}
              <div className="pointer-events-auto flex items-center gap-2 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 px-3 py-1.5 shadow-lg">
                <span className="text-base leading-none">{getFlagEmoji(geo?.country_code)}</span>
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-1">
                    {geo?.city ? `${geo.city}, ` : ''}
                    {geo?.country || 'Unknown Region'}
                  </div>
                  <div className="text-[10px] font-mono text-cyan-400">
                    {formatCoords(lat, lng)}
                  </div>
                </div>
              </div>

              {/* ISP & ASN Badge */}
              {geo?.isp && (
                <div className="pointer-events-auto flex items-center gap-2 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 px-2.5 py-1 text-[11px] shadow-lg">
                  <Server className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                  <span className="text-slate-300 truncate max-w-[200px]" title={geo.isp}>
                    {geo.isp}
                  </span>
                  {geo.asn && (
                    <span className="rounded bg-cyan-950 border border-cyan-500/30 px-1 py-0.5 text-[9px] font-mono font-bold text-cyan-300">
                      {geo.asn}
                    </span>
                  )}
                </div>
              )}

              {/* Local Server Time Badge */}
              {localTime && (
                <div className="pointer-events-auto flex items-center gap-1.5 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 px-2.5 py-1 text-[10px] font-mono text-slate-300 shadow-lg">
                  <Clock className="h-3 w-3 text-cyan-400" />
                  <span>Server Time: {localTime}</span>
                </div>
              )}
            </div>

            {/* Custom Interactive Map Controls (Top-Right) */}
            <div className="absolute top-3 right-3 z-[400] flex flex-col gap-1.5">
              <button
                onClick={handleZoomIn}
                title="Zoom In"
                className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 text-slate-300 hover:text-white hover:border-cyan-500/40 shadow-lg transition-colors"
              >
                <ZoomIn className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={handleZoomOut}
                title="Zoom Out"
                className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 text-slate-300 hover:text-white hover:border-cyan-500/40 shadow-lg transition-colors"
              >
                <ZoomOut className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={handleResetCenter}
                title="Center on Server Marker"
                className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 shadow-lg transition-colors"
              >
                <RotateCcw className="h-3.5 w-3.5" />
              </button>
            </div>
          </>
        ) : (
          /* Graceful Fallback for Localhost / Private IPs / Offline Geolocation */
          <div className="flex h-full w-full flex-col items-center justify-center bg-slate-950/90 p-6 text-center">
            <div className="relative mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-slate-900 border border-slate-800">
              <Globe className="h-8 w-8 text-slate-600 animate-pulse" />
              <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping"></div>
            </div>
            <h5 className="text-sm font-bold text-white mb-1">
              {geo?.is_private ? 'Private / Internal Network Server' : 'Physical Location Unavailable'}
            </h5>
            <p className="max-w-md text-xs text-slate-400 mb-4">
              {geo?.is_private
                ? `The target resolves to ${ip || 'a private IP address'}, which is an RFC1918 internal address or loopback. Private networks have no public physical geolocation coordinates.`
                : `Resolved public server IP: ${ip || 'Unknown'}. Geolocation service could not pinpoint exact datacenter coordinates.`}
            </p>
            <div className="flex flex-wrap items-center justify-center gap-2 font-mono text-xs">
              <span className="rounded bg-slate-900 border border-slate-800 px-2.5 py-1 text-slate-300">
                IP: <strong className="text-cyan-400">{ip || 'N/A'}</strong>
              </span>
              <span className="rounded bg-slate-900 border border-slate-800 px-2.5 py-1 text-slate-300">
                Host: <strong className="text-cyan-400">{hostname}</strong>
              </span>
              {geo?.isp && (
                <span className="rounded bg-slate-900 border border-slate-800 px-2.5 py-1 text-slate-300">
                  Network: <strong className="text-slate-200">{geo.isp}</strong>
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Technical Intelligence Strip */}
      {showDetailsPanel && (
        <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-y sm:divide-y-0 divide-slate-800 border-t border-slate-800 bg-slate-950/60 text-xs">
          <div className="p-3">
            <span className="block text-[10px] font-mono text-slate-500 uppercase">Physical Region</span>
            <span className="font-semibold text-white flex items-center gap-1.5 mt-0.5">
              <span>{getFlagEmoji(geo?.country_code)}</span>
              <span className="truncate">
                {geo?.city ? `${geo.city}, ` : ''}{geo?.country || 'Unknown'}
              </span>
            </span>
          </div>

          <div className="p-3">
            <span className="block text-[10px] font-mono text-slate-500 uppercase">Autonomous System (ASN)</span>
            <span className="font-mono font-semibold text-cyan-300 truncate block mt-0.5">
              {geo?.asn ? `${geo.asn}` : 'N/A'}
            </span>
          </div>

          <div className="p-3">
            <span className="block text-[10px] font-mono text-slate-500 uppercase">ISP / Hosting Provider</span>
            <span className="font-semibold text-white truncate block mt-0.5" title={geo?.isp}>
              {geo?.isp || 'Cloud Network'}
            </span>
          </div>

          <div className="p-3">
            <span className="block text-[10px] font-mono text-slate-500 uppercase">GPS Coordinates</span>
            <span className="font-mono text-[11px] text-slate-300 truncate block mt-0.5">
              {hasValidCoords ? `${lat.toFixed(4)}, ${lng.toFixed(4)}` : 'N/A'}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
