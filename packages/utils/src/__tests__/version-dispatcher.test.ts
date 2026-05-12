import { describe, expect, it, vi } from "vitest";

import { IoWalletSdkConfig, ItWalletSpecsVersion } from "../config";
import {
  createVersionDispatcher,
  dispatchByVersion,
} from "../version-dispatcher";

const makeOptions = (version: ItWalletSpecsVersion) => ({
  config: new IoWalletSdkConfig({ itWalletSpecsVersion: version }),
});

describe("createVersionDispatcher", () => {
  it("calls the V1_0 handler when config version is V1_0", () => {
    const v1_0Handler = vi.fn().mockReturnValue("result-v1.0");
    const v1_3Handler = vi.fn().mockReturnValue("result-v1.3");

    const dispatch = createVersionDispatcher("testFeature", {
      [ItWalletSpecsVersion.V1_0]: v1_0Handler,
      [ItWalletSpecsVersion.V1_3]: v1_3Handler,
    });

    const result = dispatch(makeOptions(ItWalletSpecsVersion.V1_0));

    expect(result).toBe("result-v1.0");
    expect(v1_0Handler).toHaveBeenCalledOnce();
    expect(v1_3Handler).not.toHaveBeenCalled();
  });

  it("calls the V1_3 handler when config version is V1_3", () => {
    const v1_0Handler = vi.fn().mockReturnValue("result-v1.0");
    const v1_3Handler = vi.fn().mockReturnValue("result-v1.3");

    const dispatch = createVersionDispatcher("testFeature", {
      [ItWalletSpecsVersion.V1_0]: v1_0Handler,
      [ItWalletSpecsVersion.V1_3]: v1_3Handler,
    });

    const result = dispatch(makeOptions(ItWalletSpecsVersion.V1_3));

    expect(result).toBe("result-v1.3");
    expect(v1_3Handler).toHaveBeenCalledOnce();
    expect(v1_0Handler).not.toHaveBeenCalled();
  });

  it("calls the V1_4 handler when config version is V1_4", () => {
    const v1_4Handler = vi.fn().mockReturnValue("result-v1.4");

    const dispatch = createVersionDispatcher("testFeature", {
      [ItWalletSpecsVersion.V1_0]: vi.fn(),
      [ItWalletSpecsVersion.V1_3]: vi.fn(),
      [ItWalletSpecsVersion.V1_4]: v1_4Handler,
    });

    const result = dispatch(makeOptions(ItWalletSpecsVersion.V1_4));

    expect(result).toBe("result-v1.4");
    expect(v1_4Handler).toHaveBeenCalledOnce();
  });

  it("throws ItWalletSpecsVersionError for an unregistered version", () => {
    const dispatch = createVersionDispatcher("myFeature", {
      [ItWalletSpecsVersion.V1_0]: vi.fn(),
    });

    const options = {
      config: { itWalletSpecsVersion: "V99_99" as ItWalletSpecsVersion },
    };

    expect(() => dispatch(options)).toThrow(
      'Feature "myFeature" does not support version V99_99',
    );
  });

  it("error message includes the accurate list of supported versions", () => {
    const dispatch = createVersionDispatcher("aFeature", {
      [ItWalletSpecsVersion.V1_0]: vi.fn(),
      [ItWalletSpecsVersion.V1_3]: vi.fn(),
    });

    const options = {
      config: { itWalletSpecsVersion: "V99_99" as ItWalletSpecsVersion },
    };

    expect(() => dispatch(options)).toThrow(
      `Supported versions: ${ItWalletSpecsVersion.V1_0}, ${ItWalletSpecsVersion.V1_3}`,
    );
  });

  it("excludes undefined handlers from supported versions in error messages", () => {
    const dispatch = createVersionDispatcher("aFeature", {
      [ItWalletSpecsVersion.V1_0]: vi.fn(),
      [ItWalletSpecsVersion.V1_3]: undefined,
    });

    const options = {
      config: { itWalletSpecsVersion: "V99_99" as ItWalletSpecsVersion },
    };

    expect(() => dispatch(options)).toThrow(
      `Supported versions: ${ItWalletSpecsVersion.V1_0}`,
    );
  });

  it("works correctly with async handlers returning Promise<T>", async () => {
    const v1_0Handler = vi.fn().mockResolvedValue("async-result-v1.0");

    const dispatch = createVersionDispatcher<
      ReturnType<typeof makeOptions>,
      Promise<string>
    >("asyncFeature", {
      [ItWalletSpecsVersion.V1_0]: v1_0Handler,
    });

    const result = await dispatch(makeOptions(ItWalletSpecsVersion.V1_0));

    expect(result).toBe("async-result-v1.0");
    expect(v1_0Handler).toHaveBeenCalledOnce();
  });

  it("passes the options object to the selected handler", () => {
    const handler = vi.fn().mockReturnValue("ok");
    const dispatch = createVersionDispatcher("testFeature", {
      [ItWalletSpecsVersion.V1_3]: handler,
    });

    const options = makeOptions(ItWalletSpecsVersion.V1_3);
    dispatch(options);

    expect(handler).toHaveBeenCalledWith(options);
  });
});

describe("dispatchByVersion", () => {
  it("calls the V1_0 handler when version is V1_0", () => {
    const v1_0Handler = vi.fn().mockReturnValue("v1.0");
    const v1_3Handler = vi.fn().mockReturnValue("v1.3");

    const result = dispatchByVersion("feature", ItWalletSpecsVersion.V1_0, {
      [ItWalletSpecsVersion.V1_0]: v1_0Handler,
      [ItWalletSpecsVersion.V1_3]: v1_3Handler,
    });

    expect(result).toBe("v1.0");
    expect(v1_0Handler).toHaveBeenCalledOnce();
    expect(v1_3Handler).not.toHaveBeenCalled();
  });

  it("calls the V1_3 handler when version is V1_3", () => {
    const v1_3Handler = vi.fn().mockReturnValue("v1.3");

    const result = dispatchByVersion("feature", ItWalletSpecsVersion.V1_3, {
      [ItWalletSpecsVersion.V1_0]: vi.fn(),
      [ItWalletSpecsVersion.V1_3]: v1_3Handler,
    });

    expect(result).toBe("v1.3");
    expect(v1_3Handler).toHaveBeenCalledOnce();
  });

  it("throws ItWalletSpecsVersionError for an unregistered version", () => {
    expect(() =>
      dispatchByVersion("aFeature", "V99_99" as ItWalletSpecsVersion, {
        [ItWalletSpecsVersion.V1_0]: vi.fn(),
      }),
    ).toThrow('Feature "aFeature" does not support version V99_99');
  });

  it("error message includes the accurate list of supported versions", () => {
    expect(() =>
      dispatchByVersion("aFeature", "V99_99" as ItWalletSpecsVersion, {
        [ItWalletSpecsVersion.V1_0]: vi.fn(),
        [ItWalletSpecsVersion.V1_3]: vi.fn(),
      }),
    ).toThrow(
      `Supported versions: ${ItWalletSpecsVersion.V1_0}, ${ItWalletSpecsVersion.V1_3}`,
    );
  });

  it("excludes undefined handlers from supported versions in error messages", () => {
    expect(() =>
      dispatchByVersion("aFeature", "V99_99" as ItWalletSpecsVersion, {
        [ItWalletSpecsVersion.V1_0]: vi.fn(),
        [ItWalletSpecsVersion.V1_3]: undefined,
      }),
    ).toThrow(`Supported versions: ${ItWalletSpecsVersion.V1_0}`);
  });

  it("works correctly with async handlers", async () => {
    const asyncHandler = vi.fn().mockResolvedValue("async-result");

    const result = await dispatchByVersion(
      "asyncFeature",
      ItWalletSpecsVersion.V1_0,
      {
        [ItWalletSpecsVersion.V1_0]: asyncHandler,
      },
    );

    expect(result).toBe("async-result");
    expect(asyncHandler).toHaveBeenCalledOnce();
  });
});
