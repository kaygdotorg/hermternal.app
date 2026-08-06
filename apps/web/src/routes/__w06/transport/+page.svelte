<!-- Non-product W-06 browser harness; it exists only to execute the exported
     transport inside the bundled browser realm without adding auth UI. -->
<script lang="ts">
  import {
    createLiveRestTransport,
    LiveRestError,
    type LiveRestFetch
  } from '$lib/transport/live-rest-transport';

  type BrowserProofCall = {
    input: string;
    method: string | null;
    credentials: RequestCredentials | null;
    cache: RequestCache | null;
    redirect: RequestRedirect | null;
    headers: Record<string, string>;
    hasBody: boolean;
    hasAuthorization: boolean;
  };

  type BrowserProofResult = {
    providers: Array<{ name: string; displayName: string; supportsPassword: boolean }>;
    calls: BrowserProofCall[];
    forbidden: Array<{ apiBaseUrl: string; errorCode: string | null }>;
    forbiddenFetcherCalls: number;
  };

  type W06ProofWindow = Window & {
    __hermternalW06BrowserProof?: () => Promise<BrowserProofResult>;
  };

  const providerBody = JSON.stringify({
    providers: [
      {
        name: 'synthetic-provider',
        display_name: 'Synthetic Provider',
        supports_password: false
      }
    ]
  });

  const forbiddenApiBaseUrls = [
    'https://attacker.invalid/api',
    '//attacker.invalid/api',
    '/api/search',
    '/api/ws-ticket'
  ];

  function toHeaders(headers: HeadersInit | undefined): Record<string, string> {
    return Object.fromEntries(new Headers(headers).entries());
  }

  if (typeof window !== 'undefined') {
    const proofWindow = window as W06ProofWindow;
    proofWindow.__hermternalW06BrowserProof = async () => {
      const calls: BrowserProofCall[] = [];
      const fetcher: LiveRestFetch = async (input, init) => {
        calls.push({
          input: String(input),
          method: init?.method ?? null,
          credentials: init?.credentials ?? null,
          cache: init?.cache ?? null,
          redirect: init?.redirect ?? null,
          headers: toHeaders(init?.headers),
          hasBody: init?.body !== undefined,
          hasAuthorization: toHeaders(init?.headers).authorization !== undefined
        });
        return new Response(providerBody, {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      };

      const transport = createLiveRestTransport({ fetch: fetcher });
      const providers = (await transport.getProviders()).providers;
      let forbiddenFetcherCalls = 0;
      const forbidden = forbiddenApiBaseUrls.map((apiBaseUrl) => {
        try {
          createLiveRestTransport({
            apiBaseUrl,
            fetch: async () => {
              forbiddenFetcherCalls += 1;
              return new Response(providerBody, {
                status: 200,
                headers: { 'content-type': 'application/json' }
              });
            }
          });
          return { apiBaseUrl, errorCode: null };
        } catch (error) {
          return {
            apiBaseUrl,
            errorCode: error instanceof LiveRestError ? error.code : 'unknown'
          };
        }
      });

      return { providers, calls, forbidden, forbiddenFetcherCalls };
    };
  }
</script>

<div aria-hidden="true" data-w06-browser-proof="ready"></div>
