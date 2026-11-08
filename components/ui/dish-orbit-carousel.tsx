"use client"

import { useRef, useState } from "react"
import { gsap } from "gsap"

export type Dish = {
  title: string
  subtitle: string
  image: string
  alt?: string
  eyebrow?: string
  label?: string
  rating: number
  chef: string
  kitchen?: string
  description: string
  likes: number
  ingredients?: string[]
  accent: string
}

export type DishOrbitCarouselProps = {
  dishes: Dish[]
  height?: string
  backdrop?: string
  loop?: boolean
  fontSrc?: string | null
  onPlay?: (dish: Dish, index: number) => void
  onOrder?: (dish: Dish, index: number) => void
  onChange?: (index: number) => void
  className?: string
}

export function wrapIndex(i: number, n: number) { return n ? ((Math.round(i) % n) + n) % n : 0 }
export function stepDirection(from: number, to: number, n: number): 1 | -1 {
  if (!n) return 1
  const fwd = ((to - from) % n + n) % n
  return fwd <= n - fwd ? 1 : -1
}

/** Compact React implementation of the orbiting dish selector. */
export function DishOrbitCarousel({ dishes, height = "min(760px, 100svh)", loop = true, onChange, onOrder, className = "" }: DishOrbitCarouselProps) {
  const [index, setIndex] = useState(0)
  const plate = useRef<HTMLImageElement>(null)
  const direction = useRef<1 | -1>(1)
  const dish = dishes[index]
  const change = (next: number) => {
    if (!dishes.length) return
    const target = loop ? wrapIndex(next, dishes.length) : Math.max(0, Math.min(dishes.length - 1, next))
    if (target === index) return
    direction.current = stepDirection(index, target, dishes.length)
    if (plate.current) gsap.fromTo(plate.current, { autoAlpha: 0, y: -28, rotation: direction.current * 18, scale: .88 }, { autoAlpha: 1, y: 0, rotation: 0, scale: 1, duration: .65, ease: "power3.out" })
    setIndex(target)
    onChange?.(target)
  }
  if (!dish) return null
  return <section className={`dish-orbit ${className}`} style={{ minHeight: height }} aria-roledescription="carousel" aria-label="Dish menu" tabIndex={0} onKeyDown={(event) => { if (event.key === "ArrowRight") change(index + 1); if (event.key === "ArrowLeft") change(index - 1) }}>
    <style>{`.dish-orbit{--accent:${dish.accent};position:relative;display:grid;grid-template-columns:1fr 1fr;align-items:center;gap:5vw;overflow:hidden;padding:clamp(28px,6vw,88px);border-radius:24px;background:radial-gradient(ellipse at 27% 50%,color-mix(in srgb,var(--accent) 18%,transparent),transparent 48%),var(--color-background,#10151f);color:var(--color-foreground,#f4f5f7);font-family:ui-sans-serif,system-ui,sans-serif}.dish-orbit img{max-width:100%;object-fit:contain}.dish-orbit-plate{width:min(100%,440px);aspect-ratio:1;justify-self:center;filter:drop-shadow(0 25px 35px #0006)}.dish-orbit-copy{position:relative;z-index:1}.dish-orbit-eyebrow{font-size:12px;opacity:.67;letter-spacing:.12em;text-transform:uppercase}.dish-orbit h2{margin:14px 0 18px;font-size:clamp(34px,6vw,72px);line-height:.95;text-transform:uppercase;letter-spacing:-.055em}.dish-orbit h2 span{display:block;font-weight:300}.dish-orbit h2 strong{display:block}.dish-orbit-copy p{max-width:440px;line-height:1.7;opacity:.72}.dish-orbit-meta{display:flex;gap:12px;align-items:center;margin:22px 0}.dish-orbit-badge{padding:10px 13px;border-radius:9px;background:var(--accent);color:#17191b;font-weight:800}.dish-orbit-actions{display:flex;gap:10px}.dish-orbit button{font:inherit;color:inherit;border:1px solid #ffffff2b;background:#ffffff0a;border-radius:999px;padding:11px 16px;cursor:pointer}.dish-orbit button:hover,.dish-orbit button[aria-current=true]{background:color-mix(in srgb,var(--accent) 38%,transparent)}.dish-orbit-dots{display:flex;flex-wrap:wrap;gap:8px;margin-top:28px}.dish-orbit-dots button{width:34px;height:34px;padding:0}.dish-orbit-order{border-color:var(--accent)!important}@media(max-width:680px){.dish-orbit{grid-template-columns:1fr;padding:24px;gap:8px}.dish-orbit-plate{width:min(68vw,300px)}.dish-orbit h2{font-size:46px}}`}</style>
    <img ref={plate} className="dish-orbit-plate" src={dish.image} alt={dish.alt ?? `${dish.title} ${dish.subtitle}`} />
    <div className="dish-orbit-copy"><div className="dish-orbit-eyebrow">{dish.eyebrow ?? `#${index + 1} Most loved dish`}</div><h2><span>{dish.title}</span><strong>{dish.subtitle}</strong></h2><div className="dish-orbit-meta"><span className="dish-orbit-badge">★ {dish.rating.toFixed(1)}</span><span>{dish.chef}{dish.kitchen ? ` · ${dish.kitchen}` : ""}</span></div><p>{dish.description}</p><div className="dish-orbit-actions"><button className="dish-orbit-order" onClick={() => onOrder?.(dish, index)}>Order food</button><span>{dish.likes} likes</span></div><div className="dish-orbit-dots" aria-label="Choose a dish">{dishes.map((item, i) => <button key={`${item.title}-${i}`} aria-label={`${item.title} ${item.subtitle}`} aria-current={i === index} onClick={() => change(i)}>{String(i + 1).padStart(2, "0")}</button>)}</div></div>
  </section>
}

export default DishOrbitCarousel
