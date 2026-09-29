"use client";

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toDataURL } from "qrcode";
import { CheckCircle2, ShieldCheck, ShieldOff } from "lucide-react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { TotpEnableResponse, TotpSetupResponse } from "@/lib/types";
import { totpCodeSchema, type TotpCodeInput } from "@/lib/validation";

/** Groups a base32 secret into 4-character blocks for manual entry —
 * `ABCD2EFG...` reads and re-types far more reliably as `ABCD 2EFG ...`. */
function formatSecretForDisplay(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

type View =
  | { step: "idle" }
  | { step: "setup"; secret: string; provisioningUri: string; qrDataUrl: string | null }
  | { step: "recovery-codes"; codes: string[] }
  | { step: "disable" };

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}

export function TwoFactorSettings({ initialEnabled }: { initialEnabled: boolean }) {
  const [enabled, setEnabled] = useState(initialEnabled);
  const [view, setView] = useState<View>({ step: "idle" });
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isStartingSetup, setIsStartingSetup] = useState(false);

  async function startSetup() {
    setLoadError(null);
    setIsStartingSetup(true);
    try {
      const setup = await clientApiFetch<TotpSetupResponse>("/auth/2fa/setup", {
        method: "POST",
      });
      let qrDataUrl: string | null = null;
      try {
        qrDataUrl = await toDataURL(setup.provisioning_uri, { margin: 1, width: 220 });
      } catch {
        // The manual-entry secret below still works without a QR code —
        // every authenticator app supports typing it in directly, so this
        // is a degraded experience, not a blocked one.
        qrDataUrl = null;
      }
      setView({
        step: "setup",
        secret: setup.secret,
        provisioningUri: setup.provisioning_uri,
        qrDataUrl,
      });
    } catch (error) {
      setLoadError(errorMessage(error, "Could not start setup. Try again."));
    } finally {
      setIsStartingSetup(false);
    }
  }

  if (view.step === "setup") {
    return (
      <EnrollmentForm
        secret={view.secret}
        provisioningUri={view.provisioningUri}
        qrDataUrl={view.qrDataUrl}
        onEnabled={(codes) => {
          setEnabled(true);
          setView({ step: "recovery-codes", codes });
        }}
        onCancel={() => setView({ step: "idle" })}
      />
    );
  }

  if (view.step === "recovery-codes") {
    return (
      <RecoveryCodesDisplay
        codes={view.codes}
        onDone={() => setView({ step: "idle" })}
      />
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {enabled ? (
            <ShieldCheck className="h-5 w-5 text-success" aria-hidden />
          ) : (
            <ShieldOff className="h-5 w-5 text-muted-foreground" aria-hidden />
          )}
          Two-factor authentication
        </CardTitle>
        <CardDescription>
          {enabled
            ? "Enabled. A code from your authenticator app is required at every sign-in."
            : "Add a second step to sign-in using a TOTP authenticator app (e.g. Google Authenticator, 1Password, Authy) — free, and works with no additional service."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {loadError && <Alert tone="destructive">{loadError}</Alert>}
        {view.step === "disable" ? (
          <DisableForm
            onDisabled={() => {
              setEnabled(false);
              setView({ step: "idle" });
            }}
            onCancel={() => setView({ step: "idle" })}
          />
        ) : enabled ? (
          <Button
            variant="destructive"
            className="self-start"
            onClick={() => setView({ step: "disable" })}
          >
            Disable two-factor authentication
          </Button>
        ) : (
          <Button className="self-start" isLoading={isStartingSetup} onClick={startSetup}>
            {isStartingSetup ? "Starting..." : "Enable two-factor authentication"}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

function EnrollmentForm({
  secret,
  provisioningUri,
  qrDataUrl,
  onEnabled,
  onCancel,
}: {
  secret: string;
  provisioningUri: string;
  qrDataUrl: string | null;
  onEnabled: (codes: string[]) => void;
  onCancel: () => void;
}) {
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<TotpCodeInput>({ resolver: zodResolver(totpCodeSchema) });

  async function onSubmit(values: TotpCodeInput) {
    setFormError(null);
    try {
      const response = await clientApiFetch<TotpEnableResponse>("/auth/2fa/enable", {
        method: "POST",
        body: JSON.stringify({ code: values.code.trim() }),
      });
      onEnabled(response.recovery_codes);
    } catch (error) {
      setFormError(errorMessage(error, "That code didn't verify. Try again."));
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Set up your authenticator app</CardTitle>
        <CardDescription>
          Scan this QR code with your authenticator app, or enter the secret manually, then
          confirm with a code it generates.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {qrDataUrl ? (
          // A locally generated data: URL, not a remote image — next/image's
          // optimizer has nothing to do here.
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={qrDataUrl}
            alt="Scan this QR code with your authenticator app"
            width={220}
            height={220}
            className="self-center rounded-lg border border-border bg-white p-2"
          />
        ) : (
          <Alert tone="info">
            Couldn&apos;t render a QR code — enter the secret below manually.
          </Alert>
        )}
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="totp-secret">Manual entry secret</Label>
          <Input
            id="totp-secret"
            readOnly
            value={formatSecretForDisplay(secret)}
            className="font-mono tracking-wider"
            onFocus={(event) => event.currentTarget.select()}
          />
          <p className="text-xs text-muted-foreground">
            Only needed if you can&apos;t scan the QR code.{" "}
            <a href={provisioningUri} className="underline">
              Open in authenticator app
            </a>
            .
          </p>
        </div>
        <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="enroll-code">Confirmation code</Label>
            <Input
              id="enroll-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              aria-invalid={!!errors.code}
              {...register("code")}
            />
            {errors.code && (
              <p className="text-sm text-destructive" role="alert">
                {errors.code.message}
              </p>
            )}
          </div>
          {formError && <Alert tone="destructive">{formError}</Alert>}
          <div className="flex gap-2">
            <Button type="submit" isLoading={isSubmitting}>
              {isSubmitting ? "Verifying..." : "Verify and enable"}
            </Button>
            <Button type="button" variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function RecoveryCodesDisplay({
  codes,
  onDone,
}: {
  codes: string[];
  onDone: () => void;
}) {
  const [copied, setCopied] = useState(false);

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch {
      // Clipboard access can be denied by the browser; the codes are still
      // fully visible and selectable on the page either way.
    }
  }

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timeout = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timeout);
  }, [copied]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-success" aria-hidden />
          Two-factor authentication is enabled
        </CardTitle>
        <CardDescription>
          Save these recovery codes somewhere safe. Each one can be used once to sign in if you
          lose access to your authenticator app.{" "}
          <strong className="text-foreground">They will not be shown again.</strong>
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-2 rounded-lg border border-border bg-muted/40 p-4 font-mono text-sm sm:grid-cols-2">
          {codes.map((code) => (
            <span key={code}>{code}</span>
          ))}
        </div>
        <div className="flex gap-2">
          <Button type="button" variant="outline" onClick={copyAll}>
            {copied ? (
              <>
                <CheckCircle2 className="h-4 w-4" aria-hidden />
                Copied
              </>
            ) : (
              "Copy all"
            )}
          </Button>
          <Button type="button" onClick={onDone}>
            I&apos;ve saved these — done
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function DisableForm({
  onDisabled,
  onCancel,
}: {
  onDisabled: () => void;
  onCancel: () => void;
}) {
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<TotpCodeInput>({ resolver: zodResolver(totpCodeSchema) });

  async function onSubmit(values: TotpCodeInput) {
    setFormError(null);
    try {
      await clientApiFetch("/auth/2fa/disable", {
        method: "POST",
        body: JSON.stringify({ code: values.code.trim() }),
      });
      onDisabled();
    } catch (error) {
      setFormError(errorMessage(error, "That code didn't verify. Try again."));
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <Alert tone="warning">
        Disabling two-factor authentication removes this extra sign-in step. Confirm with a
        current code or a recovery code.
      </Alert>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="disable-code">Authentication code</Label>
        <Input
          id="disable-code"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="123456"
          aria-invalid={!!errors.code}
          {...register("code")}
        />
        {errors.code && (
          <p className="text-sm text-destructive" role="alert">
            {errors.code.message}
          </p>
        )}
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" variant="destructive" isLoading={isSubmitting}>
          {isSubmitting ? "Disabling..." : "Confirm disable"}
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
