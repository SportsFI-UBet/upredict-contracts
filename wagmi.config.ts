import { defineConfig } from "@wagmi/cli";
import { foundry, foundryDefaultExcludes } from "@wagmi/cli/plugins";

export default defineConfig({
  out: "generated/wagmi.ts",
  contracts: [],
  plugins: [
    foundry({
      project: ".",
      exclude: [...foundryDefaultExcludes, "proxy/**.sol/**"],
    }),
  ],
});
