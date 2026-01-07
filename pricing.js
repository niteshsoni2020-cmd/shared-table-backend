"use strict";

/*
  FINAL LOCKED PRICING, DISCOUNT, PLATFORM FEE & REFUND MODEL
  Pure functions only (no mongoose here).
*/

function _isFiniteInt(n) {
  return Number.isFinite(n) && Math.floor(n) === n;
}

function _round(n) {
  return Math.round(n);
}

function _clamp(n, lo, hi) {
  const x = Number(n);
  if (!Number.isFinite(x)) return lo;
  return Math.max(lo, Math.min(hi, x));
}

function _requireInt(name, v) {
  if (!_isFiniteInt(v)) {
    throw new Error("PRICING_INVALID_INT_" + String(name));
  }
  if (v < 0) {
    throw new Error("PRICING_NEGATIVE_" + String(name));
  }
  return v;
}

function computePlatformFeeCentsGross(args) {
  const hostBasePriceCents = _requireInt("hostBasePriceCents", args.hostBasePriceCents);
  const p = args.platformFeePolicy || null;

  if (!p || typeof p !== "object") {
    return {
      platformFeeCentsGross: 0,
      platformFeeType: "",
      platformFeePctApplied: 0,
      platformFeeCentsApplied: 0,
      platformFeePolicyId: "",
      platformFeeEffectiveAt: null
    };
  }

  const t = String(p.type || "");
  const policyId = p.policyId != null ? String(p.policyId) : "";
  const effectiveFrom = p.effectiveFrom != null ? p.effectiveFrom : null;

  if (t !== "PERCENT" && t !== "FLAT" && t !== "TIERED") {
    throw new Error("PLATFORM_FEE_INVALID_TYPE");
  }

  let feeGross = 0;
  let feePctApplied = 0;
  let feeCentsApplied = 0;

  if (t === "PERCENT") {
    const pct = Number(p.value);
    if (!Number.isFinite(pct) || pct < 0) throw new Error("PLATFORM_FEE_INVALID_PERCENT");
    feePctApplied = pct;
    feeGross = _round(hostBasePriceCents * (pct / 100));
  } else if (t === "FLAT") {
    const cents = _round(Number(p.value));
    if (!_isFiniteInt(cents) || cents < 0) throw new Error("PLATFORM_FEE_INVALID_FLAT");
    feeCentsApplied = cents;
    feeGross = cents;
  } else {
    const tiers = Array.isArray(p.tiers) ? p.tiers : [];
    let matched = null;
    for (const tier of tiers) {
      if (!tier) continue;
      const min = _round(Number(tier.minHostBaseCents));
      const max = _round(Number(tier.maxHostBaseCents));
      if (!_isFiniteInt(min) || !_isFiniteInt(max) || min < 0 || max < min) continue;
      if (hostBasePriceCents < min || hostBasePriceCents > max) continue;
      matched = tier;
      break;
    }
    if (!matched) {
      feeGross = 0;
    } else if (matched.feePct != null) {
      const pct = Number(matched.feePct);
      if (!Number.isFinite(pct) || pct < 0) throw new Error("PLATFORM_FEE_TIER_INVALID");
      feePctApplied = pct;
      feeGross = _round(hostBasePriceCents * (pct / 100));
    } else if (matched.feeCents != null) {
      const cents = _round(Number(matched.feeCents));
      if (!_isFiniteInt(cents) || cents < 0) throw new Error("PLATFORM_FEE_TIER_INVALID");
      feeCentsApplied = cents;
      feeGross = cents;
    } else {
      throw new Error("PLATFORM_FEE_TIER_INVALID");
    }
  }

  feeGross = _requireInt("platformFeeCentsGross", _round(feeGross));

  return {
    platformFeeCentsGross: feeGross,
    platformFeeType: t,
    platformFeePctApplied: feePctApplied,
    platformFeeCentsApplied: feeCentsApplied,
    platformFeePolicyId: policyId,
    platformFeeEffectiveAt: effectiveFrom
  };
}

function computeDiscountsAndPromo(args) {
  const hostBasePriceCents = _requireInt("hostBasePriceCents", args.hostBasePriceCents);

  const hostPctApplied = _clamp(Number(args.hostPct || 0), 0, 50);
  const adminPctApplied = _clamp(Number(args.adminPct || 0), 0, 50 - hostPctApplied);

  const priceDiscountPctApplied = hostPctApplied + adminPctApplied;

  const priceDiscountedHostCents = _requireInt(
    "priceDiscountedHostCents",
    _round(hostBasePriceCents * (100 - priceDiscountPctApplied) / 100)
  );

  const promoPctRequested = _clamp(Number(args.promoPctRequested || 0), 0, 50);

  let promoEligible = true;
  let promoIneligibleReasonCode = "";

  if (!(priceDiscountPctApplied < 40)) {
    promoEligible = false;
    promoIneligibleReasonCode = "PROMO_INELIGIBLE_DISCOUNT_GTE_40";
  } else if (!((50 - priceDiscountPctApplied) >= 10)) {
    promoEligible = false;
    promoIneligibleReasonCode = "PROMO_INELIGIBLE_HEADROOM_LT_10";
  }

  let promoPctApplied = 0;
  let finalHostChargeCents = priceDiscountedHostCents;

  if (promoPctRequested > 0) {
    if (!promoEligible) {
      return {
        hostPctApplied,
        adminPctApplied,
        priceDiscountPctApplied,
        priceDiscountedHostCents,
        promoPctRequested,
        promoPctApplied: 0,
        promoIneligibleReasonCode,
        finalHostChargeCents
      };
    }

    promoPctApplied = _clamp(promoPctRequested, 0, 50 - priceDiscountPctApplied);
    finalHostChargeCents = _requireInt(
      "finalHostChargeCents",
      _round(priceDiscountedHostCents * (100 - promoPctApplied) / 100)
    );
  }

  return {
    hostPctApplied,
    adminPctApplied,
    priceDiscountPctApplied,
    priceDiscountedHostCents,
    promoPctRequested,
    promoPctApplied,
    promoIneligibleReasonCode,
    finalHostChargeCents
  };
}

function computeGuestDisplayedPriceCents(args) {
  const a = _requireInt("finalHostChargeCents", args.finalHostChargeCents);
  const b = _requireInt("platformFeeCentsGross", args.platformFeeCentsGross);
  return _requireInt("guestDisplayedPriceCents", a + b);
}

function computeHostPayoutAndSubsidy(args) {
  const base = _requireInt("hostBasePriceCents", args.hostBasePriceCents);
  const hostPctApplied = _clamp(Number(args.hostPctApplied || 0), 0, 50);
  const finalHostChargeCents = _requireInt("finalHostChargeCents", args.finalHostChargeCents);

  const hostPayoutCents = _requireInt(
    "hostPayoutCents",
    _round(base * (100 - hostPctApplied) / 100)
  );

  const adminSubsidyCents = _requireInt(
    "adminSubsidyCents",
    hostPayoutCents - finalHostChargeCents
  );

  if (finalHostChargeCents + adminSubsidyCents !== hostPayoutCents) {
    throw new Error("PRICING_INVARIANT_FAIL_HOSTPAYOUT");
  }

  return { hostPayoutCents, adminSubsidyCents };
}

function computeRefundCents(args) {
  const paid = _requireInt("guestDisplayedPriceCents", args.guestDisplayedPriceCents);
  return {
    refundPct: 95,
    refundCents: _requireInt("refundCents", _round(paid * 95 / 100))
  };
}

module.exports = {
  computePlatformFeeCentsGross,
  computeDiscountsAndPromo,
  computeGuestDisplayedPriceCents,
  computeHostPayoutAndSubsidy,
  computeRefundCents
};
