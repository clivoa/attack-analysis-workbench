import './css/style.css'
import * as d3 from 'd3'
import { initApp } from './js/app.js'
import { Graph } from './js/graph.js'
import { Matrix } from './js/matrix.js'
import { Detect } from './js/detect.js'
import { Defense } from './js/defense.js'
import { Panel } from './js/panel.js'
import { Tour } from './js/tour.js'

// Expose D3 and modules globally for compatibility
window.d3 = d3
window.Graph = Graph
window.Matrix = Matrix
window.Detect = Detect
window.Defense = Defense
window.Panel = Panel
window.Tour = Tour

// Initialize the app
initApp()
