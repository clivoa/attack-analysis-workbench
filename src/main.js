import './css/style.css'
import * as d3 from 'd3'
import { initApp } from './js/app.js'
import { Graph } from './js/graph.js'
import { Matrix } from './js/matrix.js'
import { Detect } from './js/detect.js'
import { Defense } from './js/defense.js'
import { Panel } from './js/panel.js'
import { Tour } from './js/tour.js'
import { Rules } from './js/rules.js'

// Expose D3 and modules globally for compatibility
window.d3 = d3
window.Graph = Graph
window.Matrix = Matrix
window.Detect = Detect
window.Defense = Defense
window.Panel = Panel
window.Tour = Tour
window.Rules = Rules

// Theme toggle — the saved theme is applied by an inline script in index.html
document.getElementById('theme-toggle').addEventListener('click', () => {
  const root = document.documentElement
  const toLight = root.getAttribute('data-theme') !== 'light'
  if (toLight) root.setAttribute('data-theme', 'light')
  else root.removeAttribute('data-theme')
  localStorage.setItem('aaw-theme', toLight ? 'light' : 'dark')
})

// Initialize the app
initApp()
