import { visit } from 'unist-util-visit';
import { fromHtml } from 'hast-util-from-html';
import tikzJax from 'node-tikzjax';

export default function rehypeTikz() {
  return async (tree) => {
    const nodes = [];
    
    // Collect all TikZ code blocks
    visit(tree, 'element', (node, index, parent) => {
      if (node.tagName === 'pre' && 
          node.children?.[0]?.tagName === 'code' && 
          node.children[0].properties?.className?.includes('language-tikz')) {
        nodes.push({ node, index, parent });
      }
    });

    // Process from last to first to prevent index shifts
    for (let i = nodes.length - 1; i >= 0; i--) {
      const { node, index, parent } = nodes[i];
      const codeNode = node.children[0];
      const tikzCode = codeNode.children.map(child => child.value).join('');
      
      try {
        const svg = await tikzJax.toSVG(tikzCode);
        
        // Convert SVG string to HAST nodes
        const svgNode = fromHtml(svg, { fragment: true });
        
        // Replace code block with SVG
        parent.children.splice(index, 1, ...svgNode.children);
      } catch (error) {
        console.error('TikZ compilation failed:', error);
        // Keep original code block on error
      }
    }
  };
}