import { THEMES } from './state.mjs';

const themeNames = Object.freeze({
  system: 'System',
  nord: 'Nord',
  dracula: 'Dracula',
  gruvbox: 'Gruvbox',
  solarized: 'Solarized',
  catppuccin: 'Catppuccin',
  'tokyo-night': 'Tokyo Night',
  'rose-pine': 'Rosé Pine',
  'one-dark': 'One Dark',
  monokai: 'Monokai',
});

const icon = (name) => {
  const paths = {
    check: '<path d="m7 12 3 3 7-7"/>',
    chevron: '<path d="m9 7 5 5-5 5"/>',
    copy: '<rect x="8" y="8" width="10" height="10" rx="2"/><path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1"/>',
    file: '<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v5h5M10 13h5M10 16h4"/>',
    refresh: '<path d="M19 7v5h-5M5 17v-5h5"/><path d="M7.1 8.5A6 6 0 0 1 18 12M6 12a6 6 0 0 0 10.9 3.5"/>',
    terminal: '<path d="m5 7 4 5-4 5M11 17h8"/>',
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name]}</svg>`;
};

function userMessage(copy, time = '10:42') {
  return `
    <article class="message message-user">
      <header class="message-meta"><span>You</span><time>${time}</time></header>
      <div class="message-body user-surface"><p>${copy}</p></div>
    </article>`;
}

function assistantMessage() {
  return `
    <article class="message message-assistant">
      <header class="message-meta"><span>Hermes</span><span>Sonnet 4.5</span></header>
      <div class="message-body assistant-prose">
        <p>A calm launch starts by giving the audience one thing to hold onto. Your notes point to a clear promise: the product removes coordination overhead without asking teams to change how they think.</p>
        <p>I’d shape the opening around that relief, then move from the familiar friction into the new behavior:</p>
        <ol>
          <li><span>Begin with the cost of fragmented attention.</span></li>
          <li><span>Show the assistant quietly carrying context forward.</span></li>
          <li><span>End on what the team can finally spend time doing.</span></li>
        </ol>
      </div>
      <footer class="message-actions" aria-label="Response actions">
        <button class="quiet-action" type="button" aria-label="Copy response">${icon('copy')}</button>
        <button class="quiet-action" type="button" aria-label="Regenerate response">${icon('refresh')}</button>
      </footer>
    </article>`;
}

function operationalStates() {
  return `
    <div class="event-row tool-event">
      <span class="event-icon">${icon('terminal')}</span>
      <div><strong>Reviewing launch-notes.md</strong><span>Extracted voice, audience, and constraints</span></div>
      <button class="event-action" type="button" data-tool-toggle aria-expanded="false">Details ${icon('chevron')}</button>
      <pre class="tool-detail" hidden><code>voice: calm, specific\naudience: product teams\nconstraint: no campaign language</code></pre>
    </div>
    <div class="event-row approval-event">
      <span class="event-icon">${icon('file')}</span>
      <div><strong>Use the attached brief as context?</strong><span>Mock approval · no file is read or uploaded</span></div>
      <div class="approval-actions">
        <button type="button" data-approval="deny">Not now</button>
        <button class="primary-compact" type="button" data-approval="allow">Allow once</button>
      </div>
    </div>`;
}

function streamingMessage() {
  return `
    <article class="message message-assistant streaming-message">
      <header class="message-meta"><span>Hermes</span><span class="stream-status"><i></i>Writing</span></header>
      <div class="message-body assistant-prose">
        <p>Here’s a tighter opening:</p>
        <p>Work rarely slows down because people lack ideas. It slows down in the spaces between them—finding context, repeating decisions, and rebuilding momentum. Hermternal keeps those threads together, so the next step is already within reach.<span class="typing-caret" aria-hidden="true"></span></p>
      </div>
      <footer class="stream-footer"><button type="button">Stop</button><span>Local simulated response</span></footer>
    </article>`;
}

export function renderVariant(lane) {
  return `
    <section class="lane lane-${lane}" data-lane="${lane}" aria-label="Conversation messages">
      <div class="lane-intro">
        <span>Today</span><time>10:42</time>
      </div>
      <div class="transcript-flow">
        <section class="conversation-turn">
          ${userMessage('Plan a calm product launch. Use the attached notes, keep the language precise, and avoid anything that sounds like a campaign.')}
          ${assistantMessage()}
          ${operationalStates()}
        </section>
        <section class="conversation-turn">
          ${userMessage('Good. Make the opening more direct and keep it under seventy words.', '10:46')}
          ${streamingMessage()}
        </section>
      </div>
    </section>`;
}

export function renderThemeOptions() {
  return THEMES.map(
    (theme, index) => `
      <button class="menu-option theme-option" type="button" role="menuitemradio" aria-checked="${index === 0}" data-theme-value="${theme}">
        <span class="theme-preview" data-preview="${theme}" aria-hidden="true"><i></i></span>
        <span>${themeNames[theme]}</span>
        ${icon('check')}
      </button>`,
  ).join('');
}

export function renderPicker() {
  return `
    <nav class="proto-picker" aria-label="Prototype variants">
      <span class="proto-picker-highlight" aria-hidden="true"></span>
      <button class="proto-picker-item" data-active aria-current="true" data-variant-index="0" aria-label="Continuous Canvas">Canvas</button>
      <button class="proto-picker-item" data-variant-index="1" aria-label="Turn Stacks">Stacks</button>
      <button class="proto-picker-item" data-variant-index="2" aria-label="Focus Lane">Focus</button>
      <span class="proto-picker-divider" aria-hidden="true"></span>
      <button class="proto-picker-item proto-picker-replay" aria-label="Replay animation (R)">↻</button>
    </nav>`;
}

export function renderLocalExchange(copy) {
  return `
    <section class="conversation-turn local-turn">
      ${userMessage(copy, 'Now')}
      <article class="message message-assistant local-response">
        <header class="message-meta"><span>Hermes</span><span class="stream-status"><i></i>Thinking</span></header>
        <div class="message-body assistant-prose"><p>I’m shaping that into the local prototype now. No message has left this browser.</p></div>
      </article>
    </section>`;
}
