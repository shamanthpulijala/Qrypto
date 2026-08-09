// ============================================================
// QuantumGuard AI — Custom Quantum Cursor §07
// Premium luminous dot + trailing ring with magnetic hover
// ============================================================

import React, { useEffect, useRef, useCallback } from 'react';
import './QuantumCursor.css';

export function QuantumCursor() {
  const dotRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);
  const mouse = useRef({ x: 0, y: 0 });
  const ringPos = useRef({ x: 0, y: 0 });
  const hovering = useRef(false);
  const rafId = useRef<number>(0);

  const animate = useCallback(() => {
    // Ring follows with slight lag (spring interpolation)
    const lerp = 0.12;
    ringPos.current.x += (mouse.current.x - ringPos.current.x) * lerp;
    ringPos.current.y += (mouse.current.y - ringPos.current.y) * lerp;

    if (dotRef.current) {
      dotRef.current.style.transform = `translate(${mouse.current.x - 4}px, ${mouse.current.y - 4}px)`;
    }
    if (ringRef.current) {
      const size = hovering.current ? 52 : 36;
      ringRef.current.style.transform = `translate(${ringPos.current.x - size / 2}px, ${ringPos.current.y - size / 2}px)`;
    }

    rafId.current = requestAnimationFrame(animate);
  }, []);

  useEffect(() => {
    // Check for touch device
    const isTouchDevice = window.matchMedia('(pointer: coarse)').matches;
    if (isTouchDevice) return;

    document.body.classList.add('custom-cursor-active');

    const onMouseMove = (e: MouseEvent) => {
      mouse.current.x = e.clientX;
      mouse.current.y = e.clientY;
    };

    const onMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const isInteractive = target.closest('button, a, input, select, textarea, [role="button"], .interactive');
      if (isInteractive) {
        hovering.current = true;
        dotRef.current?.classList.add('hovering');
        ringRef.current?.classList.add('hovering');
      }
    };

    const onMouseOut = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const isInteractive = target.closest('button, a, input, select, textarea, [role="button"], .interactive');
      if (isInteractive) {
        hovering.current = false;
        dotRef.current?.classList.remove('hovering');
        ringRef.current?.classList.remove('hovering');
      }
    };

    window.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseover', onMouseOver);
    document.addEventListener('mouseout', onMouseOut);

    rafId.current = requestAnimationFrame(animate);

    return () => {
      document.body.classList.remove('custom-cursor-active');
      window.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseover', onMouseOver);
      document.removeEventListener('mouseout', onMouseOut);
      cancelAnimationFrame(rafId.current);
    };
  }, [animate]);

  return (
    <>
      <div ref={dotRef} className="quantum-cursor-dot" />
      <div ref={ringRef} className="quantum-cursor-ring" />
    </>
  );
}
