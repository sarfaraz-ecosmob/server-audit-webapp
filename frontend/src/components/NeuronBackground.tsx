"use client";

import { useEffect, useRef } from "react";

type P = { x: number; y: number; vx: number; vy: number; size: number; teal: boolean };

/**
 * Ambient particle-network background. Purely decorative — mounted once per
 * page behind real content (position: fixed, pointer-events: none), so it
 * never intercepts clicks and never affects layout. `density` scales particle
 * count; use a lower value for pages with dense data (dashboards) and 1 for
 * a hero moment like the login screen.
 */
export default function NeuronBackground({
  density = 1,
  opacity = 1,
}: {
  density?: number;
  opacity?: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let w = 0;
    let h = 0;
    let raf = 0;
    let visible = !document.hidden;

    function resize() {
      w = canvas!.width = window.innerWidth;
      h = canvas!.height = window.innerHeight;
    }
    resize();
    window.addEventListener("resize", resize);

    const mouse = { x: -9999, y: -9999, radius: 130 };
    function onMove(e: MouseEvent) {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    }
    function onLeave() {
      mouse.x = -9999;
      mouse.y = -9999;
    }
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseleave", onLeave);

    function onVisibility() {
      visible = !document.hidden;
      if (visible) tick();
    }
    document.addEventListener("visibilitychange", onVisibility);

    const count = reduceMotion ? 0 : Math.min(Math.floor((window.innerWidth / 16) * density), 130);
    const particles: P[] = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45,
      size: Math.random() * 1.5 + 0.7,
      teal: Math.random() > 0.3,
    }));

    const TEAL = "79, 209, 197"; // matches --accent
    const BLUE = "124, 156, 255"; // matches --accent2

    function draw() {
      ctx!.clearRect(0, 0, w, h);

      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;

        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          p.x -= dx * 0.0015;
          p.y -= dy * 0.0015;
        }

        ctx!.beginPath();
        ctx!.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(${p.teal ? TEAL : BLUE}, 0.85)`;
        ctx!.fill();
      }

      for (let a = 0; a < particles.length; a++) {
        for (let b = a + 1; b < particles.length; b++) {
          const dx = particles[a].x - particles[b].x;
          const dy = particles[a].y - particles[b].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 105) {
            ctx!.beginPath();
            ctx!.moveTo(particles[a].x, particles[a].y);
            ctx!.lineTo(particles[b].x, particles[b].y);
            ctx!.strokeStyle = `rgba(${TEAL}, ${(1 - dist / 105) * 0.45})`;
            ctx!.lineWidth = 0.6;
            ctx!.stroke();
          }
        }
      }
    }

    function tick() {
      if (!visible) return;
      draw();
      raf = requestAnimationFrame(tick);
    }

    if (!reduceMotion) tick();
    else draw(); // count is 0 in this case, so this just clears the canvas

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseleave", onLeave);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [density]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="fixed inset-0 pointer-events-none"
      style={{ zIndex: 0, opacity }}
    />
  );
}
