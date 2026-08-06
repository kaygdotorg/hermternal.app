import { execFileSync } from "node:child_process";
import { readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";

const sourcePath = fileURLToPath(
  new URL("../../src/lib/chat/ws-ticket.ts", import.meta.url),
);
const bundlePath = join(
  tmpdir(),
  `hermternal-ws-ticket-${process.pid}-${randomUUID()}.mjs`,
);
execFileSync("bun", [
  "build",
  sourcePath,
  "--target=browser",
  "--format=esm",
  "--outfile",
  bundlePath,
]);
const browserModule = readFileSync(bundlePath, "utf8");
unlinkSync(bundlePath);
const browserModuleUrl = `data:text/javascript;base64,${Buffer.from(browserModule).toString("base64")}`;

function opaqueTicket(): string {
  return randomUUID().replaceAll("-", "");
}

test("real browser acquisition keeps the ticket only in the ephemeral upgrade URL", async ({
  page,
  baseURL,
}) => {
  const ticket = opaqueTicket();
  const expectedOrigin = new URL(baseURL ?? "http://127.0.0.1:4173").origin;
  let requestMethod = "";
  let requestOrigin = "";
  let hasAuthorizationHeader = false;
  let hasExplicitCookieHeader = false;

  await page.route("**/api/auth/ws-ticket", async (route) => {
    const request = route.request();
    requestMethod = request.method();
    requestOrigin = new URL(request.url()).origin;
    const headers = request.headers();
    hasAuthorizationHeader = "authorization" in headers;
    hasExplicitCookieHeader = "cookie" in headers;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ticket }),
    });
  });

  await page.goto("/");
  const result = await page.evaluate(
    async ({ moduleUrl, expectedTicket }) => {
      const module = await import(moduleUrl);
      const consoleMessages: string[] = [];
      const originalError = console.error;
      console.error = (...values: unknown[]) => {
        consoleMessages.push(values.map((value) => String(value)).join(" "));
      };

      try {
        const client = module.createWsTicketClient({
          request: module.createWsTicketRequestBoundary(
            window.fetch.bind(window),
          ),
          connect: async (upgradeUrl: URL) => ({
            sameOrigin:
              upgradeUrl.host === location.host &&
              ((upgradeUrl.protocol === "ws:" &&
                location.protocol === "http:") ||
                (upgradeUrl.protocol === "wss:" &&
                  location.protocol === "https:")),
            path: upgradeUrl.pathname === "/api/ws",
            onlyTicketQuery:
              [...upgradeUrl.searchParams.keys()].length === 1 &&
              upgradeUrl.searchParams.has("ticket"),
            noLegacyToken: !upgradeUrl.searchParams.has("token"),
            noFragment: upgradeUrl.hash === "",
            expectedTicket:
              upgradeUrl.searchParams.get("ticket") === expectedTicket,
          }),
        });
        const upgrade = await client.open();
        const rendered = document.documentElement.outerHTML;
        const currentUrl = location.href;
        const storageValues = [
          ...Object.values(localStorage),
          ...Object.values(sessionStorage),
        ].join("|");

        return {
          upgrade,
          domRedacted: !rendered.includes(expectedTicket),
          historyRedacted: !currentUrl.includes(expectedTicket),
          storageRedacted: !storageValues.includes(expectedTicket),
          logsRedacted: !consoleMessages.some((message) =>
            message.includes(expectedTicket),
          ),
        };
      } finally {
        console.error = originalError;
      }
    },
    { moduleUrl: browserModuleUrl, expectedTicket: ticket },
  );

  expect(requestMethod).toBe("POST");
  expect(requestOrigin).toBe(expectedOrigin);
  expect(hasAuthorizationHeader).toBe(false);
  expect(hasExplicitCookieHeader).toBe(false);
  expect(result).toEqual({
    upgrade: {
      sameOrigin: true,
      path: true,
      onlyTicketQuery: true,
      noLegacyToken: true,
      noFragment: true,
      expectedTicket: true,
    },
    domRedacted: true,
    historyRedacted: true,
    storageRedacted: true,
    logsRedacted: true,
  });
});

test("real browser cancellation does not create an upgrade or an automatic retry", async ({
  page,
}) => {
  let requestCount = 0;
  await page.route("**/api/auth/ws-ticket", async (route) => {
    requestCount += 1;
    await new Promise((resolve) => setTimeout(resolve, 150));
    try {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ticket: opaqueTicket() }),
      });
    } catch {
      // The page may abort the request before the delayed synthetic response.
    }
  });

  await page.goto("/");
  const result = await page.evaluate(async (moduleUrl) => {
    const module = await import(moduleUrl);
    const controller = new AbortController();
    let connectCount = 0;
    const client = module.createWsTicketClient({
      request: module.createWsTicketRequestBoundary(window.fetch.bind(window)),
      connect: async () => {
        connectCount += 1;
        return "connected";
      },
    });

    const attempt = client.open(controller.signal);
    controller.abort();
    try {
      await attempt;
      return { code: "unexpected-success", connectCount };
    } catch (error) {
      const code =
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        typeof (error as { code?: unknown }).code === "string"
          ? (error as { code: string }).code
          : "unknown";
      return {
        code,
        name: error instanceof Error ? error.name : "unknown",
        connectCount,
      };
    }
  }, browserModuleUrl);

  expect(requestCount).toBeLessThanOrEqual(1);
  expect(result).toEqual({
    code: "cancelled",
    name: "AbortError",
    connectCount: 0,
  });
});

test("real browser retry is explicit and redacts an authentication response", async ({
  page,
}) => {
  const responseMarker = opaqueTicket();
  const freshTicket = opaqueTicket();
  let requestCount = 0;

  await page.route("**/api/auth/ws-ticket", async (route) => {
    requestCount += 1;
    if (requestCount === 1) {
      await route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ detail: `Bearer ${responseMarker}` }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ticket: freshTicket }),
    });
  });

  await page.goto("/");
  const result = await page.evaluate(
    async ({ moduleUrl, marker }) => {
      const module = await import(moduleUrl);
      let connectCount = 0;
      const client = module.createWsTicketClient({
        request: module.createWsTicketRequestBoundary(
          window.fetch.bind(window),
        ),
        connect: async () => {
          connectCount += 1;
          return "connected";
        },
      });

      let firstError: unknown;
      try {
        await client.open();
      } catch (error) {
        firstError = error;
      }
      const countBeforeRetry = connectCount;
      const secondResult = await client.retry();

      const firstCode =
        typeof firstError === "object" &&
        firstError !== null &&
        "code" in firstError &&
        typeof (firstError as { code?: unknown }).code === "string"
          ? (firstError as { code: string }).code
          : "unknown";
      return {
        firstCode,
        firstMessageRedacted:
          firstError instanceof Error
            ? !firstError.message.includes(marker)
            : false,
        countBeforeRetry,
        secondResult,
        connectCount,
      };
    },
    { moduleUrl: browserModuleUrl, marker: responseMarker },
  );

  expect(requestCount).toBe(2);
  expect(result).toEqual({
    firstCode: "authentication-failed",
    firstMessageRedacted: true,
    countBeforeRetry: 0,
    secondResult: "connected",
    connectCount: 1,
  });
});
