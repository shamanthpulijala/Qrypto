// ============================================================
// Qrypto AI Advisor — 3D Interactive Quantum Computer Hero §08
// Cursor-reactive superconducting processor with particles,
// metallic rings, qubit nodes, and energy fields
// ============================================================

import React, { useRef, useMemo, useEffect } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Float } from '@react-three/drei';
import * as THREE from 'three';

// ─── Cursor-reactive orbital ring ─────────────────────────────
function OrbitalRing({ radius, thickness, speed, axis, color, opacity }: {
  radius: number; thickness: number; speed: number; axis: [number, number, number];
  color: string; opacity: number;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const mouseInfluence = useRef(0);

  useFrame((state) => {
    if (!meshRef.current) return;
    const t = state.clock.elapsedTime;
    // Base rotation
    meshRef.current.rotation.x = axis[0] * t * speed;
    meshRef.current.rotation.y = axis[1] * t * speed;
    meshRef.current.rotation.z = axis[2] * t * speed;
    // Subtle breathing
    const scale = 1 + Math.sin(t * 0.5) * 0.02;
    meshRef.current.scale.setScalar(scale);
  });

  return (
    <mesh ref={meshRef}>
      <torusGeometry args={[radius, thickness, 32, 100]} />
      <meshStandardMaterial
        color={color}
        transparent
        opacity={opacity}
        metalness={0.9}
        roughness={0.2}
        emissive={color}
        emissiveIntensity={0.15}
      />
    </mesh>
  );
}

// ─── Qubit node on ring ───────────────────────────────────────
function QubitNode({ position, color, pulseSpeed }: {
  position: [number, number, number]; color: string; pulseSpeed: number;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const glowRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (!meshRef.current) return;
    const t = state.clock.elapsedTime;
    const pulse = 1 + Math.sin(t * pulseSpeed) * 0.3;
    meshRef.current.scale.setScalar(pulse);
    if (glowRef.current) {
      glowRef.current.scale.setScalar(pulse * 2.5);
    }
  });

  return (
    <group position={position}>
      <mesh ref={meshRef}>
        <sphereGeometry args={[0.06, 16, 16]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.8} metalness={0.5} roughness={0.3} />
      </mesh>
      <mesh ref={glowRef}>
        <sphereGeometry args={[0.06, 16, 16]} />
        <meshBasicMaterial color={color} transparent opacity={0.1} />
      </mesh>
    </group>
  );
}

// ─── Floating particles ───────────────────────────────────────
function QuantumParticles({ count = 200 }: { count?: number }) {
  const meshRef = useRef<THREE.InstancedMesh>(null);
  const mousePos = useRef(new THREE.Vector2(0, 0));

  const particles = useMemo(() => {
    const data = [];
    for (let i = 0; i < count; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = 1.2 + Math.random() * 2.5;
      data.push({
        position: new THREE.Vector3(
          r * Math.sin(phi) * Math.cos(theta),
          r * Math.sin(phi) * Math.sin(theta),
          r * Math.cos(phi)
        ),
        velocity: new THREE.Vector3(
          (Math.random() - 0.5) * 0.003,
          (Math.random() - 0.5) * 0.003,
          (Math.random() - 0.5) * 0.003
        ),
        speed: 0.2 + Math.random() * 0.8,
        offset: Math.random() * Math.PI * 2,
      });
    }
    return data;
  }, [count]);

  const dummy = useMemo(() => new THREE.Object3D(), []);

  useFrame((state) => {
    if (!meshRef.current) return;
    const t = state.clock.elapsedTime;

    particles.forEach((p, i) => {
      // Orbit around center
      const angle = t * p.speed * 0.2 + p.offset;
      const x = p.position.x + Math.sin(angle) * 0.1;
      const y = p.position.y + Math.cos(angle * 0.7) * 0.1;
      const z = p.position.z + Math.sin(angle * 0.5) * 0.1;

      dummy.position.set(x, y, z);
      const scale = 0.3 + Math.sin(t * p.speed + p.offset) * 0.15;
      dummy.scale.setScalar(scale);
      dummy.updateMatrix();
      meshRef.current!.setMatrixAt(i, dummy.matrix);
    });

    meshRef.current.instanceMatrix.needsUpdate = true;
  });

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, count]}>
      <sphereGeometry args={[0.015, 8, 8]} />
      <meshBasicMaterial color="#7c3aed" transparent opacity={0.5} />
    </instancedMesh>
  );
}

// ─── Energy pulse lines ───────────────────────────────────────
function EnergyLines() {
  const groupRef = useRef<THREE.Group>(null);
  
  const lines = useMemo(() => {
    const result = [];
    for (let i = 0; i < 8; i++) {
      const angle = (i / 8) * Math.PI * 2;
      const points = [];
      for (let j = 0; j < 20; j++) {
        const t = j / 19;
        const r = 0.4 + t * 1.8;
        points.push(new THREE.Vector3(
          Math.cos(angle + t * 0.5) * r,
          (t - 0.5) * 1.5,
          Math.sin(angle + t * 0.5) * r
        ));
      }
      result.push(points);
    }
    return result;
  }, []);

  useFrame((state) => {
    if (!groupRef.current) return;
    groupRef.current.rotation.y = state.clock.elapsedTime * 0.05;
  });

  return (
    <group ref={groupRef}>
      {lines.map((points, i) => {
        const curve = new THREE.CatmullRomCurve3(points);
        const tubePoints = curve.getPoints(50);
        const geometry = new THREE.BufferGeometry().setFromPoints(tubePoints);
        return (
          <line key={i}>
            <bufferGeometry attach="geometry" {...geometry} />
            <lineBasicMaterial color="#7c3aed" transparent opacity={0.12} />
          </line>
        );
      })}
    </group>
  );
}

// ─── Central processor core ───────────────────────────────────
function ProcessorCore() {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (!meshRef.current) return;
    meshRef.current.rotation.y = state.clock.elapsedTime * 0.15;
    meshRef.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.3) * 0.1;
  });

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <mesh ref={meshRef}>
        <octahedronGeometry args={[0.35, 0]} />
        <meshStandardMaterial
          color="#7c3aed"
          transparent
          opacity={0.6}
          metalness={1}
          roughness={0.1}
          emissive="#7c3aed"
          emissiveIntensity={0.3}
        />
      </mesh>
      {/* Inner glow */}
      <mesh>
        <sphereGeometry args={[0.25, 32, 32]} />
        <meshBasicMaterial color="#7c3aed" transparent opacity={0.08} />
      </mesh>
    </Float>
  );
}

// ─── Mouse-reactive camera control ────────────────────────────
function MouseReactiveCamera() {
  const { camera } = useThree();
  const mouseRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const handleMove = (e: MouseEvent) => {
      mouseRef.current.x = (e.clientX / window.innerWidth - 0.5) * 2;
      mouseRef.current.y = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener('mousemove', handleMove);
    return () => window.removeEventListener('mousemove', handleMove);
  }, []);

  useFrame(() => {
    const targetX = mouseRef.current.x * 0.3;
    const targetY = -mouseRef.current.y * 0.2;
    camera.position.x += (targetX - camera.position.x) * 0.03;
    camera.position.y += (targetY - camera.position.y) * 0.03;
    camera.lookAt(0, 0, 0);
  });

  return null;
}

// ─── Main Scene ───────────────────────────────────────────────
function QuantumScene() {
  const qubitPositions: [number, number, number][] = useMemo(() => {
    const positions: [number, number, number][] = [];
    // Ring 1 qubits
    for (let i = 0; i < 6; i++) {
      const a = (i / 6) * Math.PI * 2;
      positions.push([Math.cos(a) * 1.2, Math.sin(a) * 1.2, 0]);
    }
    // Ring 2 qubits
    for (let i = 0; i < 8; i++) {
      const a = (i / 8) * Math.PI * 2;
      positions.push([0, Math.cos(a) * 1.7, Math.sin(a) * 1.7]);
    }
    // Ring 3 qubits
    for (let i = 0; i < 5; i++) {
      const a = (i / 5) * Math.PI * 2;
      positions.push([Math.cos(a) * 2.2, 0, Math.sin(a) * 2.2]);
    }
    return positions;
  }, []);

  return (
    <>
      {/* Lighting */}
      <ambientLight intensity={0.15} />
      <pointLight position={[3, 3, 3]} intensity={0.6} color="#7c3aed" />
      <pointLight position={[-3, -2, 2]} intensity={0.3} color="#00d4ff" />
      <pointLight position={[0, 0, 0]} intensity={0.4} color="#7c3aed" />

      {/* Camera reactivity */}
      <MouseReactiveCamera />

      {/* Core processor */}
      <ProcessorCore />

      {/* Orbital rings */}
      <OrbitalRing radius={1.2} thickness={0.015} speed={0.15} axis={[0, 1, 0.2]} color="#7c3aed" opacity={0.5} />
      <OrbitalRing radius={1.7} thickness={0.012} speed={0.1} axis={[0.5, 0, 1]} color="#00d4ff" opacity={0.35} />
      <OrbitalRing radius={2.2} thickness={0.01} speed={0.08} axis={[0, 0.3, 1]} color="#8b5cf6" opacity={0.25} />
      <OrbitalRing radius={2.8} thickness={0.008} speed={0.05} axis={[0.7, 1, 0]} color="#312e81" opacity={0.15} />

      {/* Qubit nodes */}
      {qubitPositions.map((pos, i) => (
        <QubitNode
          key={i}
          position={pos}
          color={i % 3 === 0 ? '#00d4ff' : i % 3 === 1 ? '#7c3aed' : '#8b5cf6'}
          pulseSpeed={1 + Math.random() * 2}
        />
      ))}

      {/* Particles */}
      <QuantumParticles count={150} />
    </>
  );
}

// ─── Exported Component ───────────────────────────────────────
export function QuantumComputer() {
  return (
    <div style={{
      position: 'absolute',
      inset: 0,
      zIndex: 0,
      opacity: 0.85,
    }}>
      <Canvas
        camera={{ position: [0, 0, 5], fov: 50 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <QuantumScene />
      </Canvas>
    </div>
  );
}
