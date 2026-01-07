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
  // Refunds must be computed from a platform-fee-safe base (typically finalHostChargeCents),
  // not from guestDisplayedPriceCents (which includes platform fee).
  const base = _requireInt("refundBaseCents", args.refundBaseCents);
  const pctRaw = Number.isFinite(Number(args.refundPct)) ? Number(args.refundPct) : 95;
  const pct = _requireInt("refundPct", _clamp(_round(pctRaw), 0, 95));
  return {
    refundPct: pct,
    refundCents: _requireInt("refundCents", _round(base * pct / 100))
  };
}

function computeBookingPricingSnapshot(args) {
  // Authoritative kernel: compute all cents here (caller supplies inputs/policy only).
  const unitCents = _requireInt("unitCents", args.unitCents);
  const guests = _requireInt("guests", args.guests);

  const isPrivate = Boolean(args.isPrivate);
  const privateHostBaseCents = (args.privateHostBaseCents != null) ? _round(Number(args.privateHostBaseCents)) : null;

  const hostPctRequested = _round(Number(args.hostPctRequested) || 0);
  const adminPctRequested = _round(Number(args.adminPctRequested) || 0);

  const promoPercentOff = _round(Number(args.promoPercentOff) || 0);
  const promoFixedOffCents = _round(Number(args.promoFixedOffCents) || 0);

  const platformFeePolicy = (args.platformFeePolicy && typeof args.platformFeePolicy === "object") ? args.platformFeePolicy : null;

  const rawSubtotalCents = _requireInt("subtotalCents", _round(unitCents * guests));

  // Host base (what discounts are applied to). Private bookings override host base.
  let hostBasePriceCents = rawSubtotalCents;
  if (isPrivate && privateHostBaseCents != null) {
    hostBasePriceCents = _requireInt("privateHostBaseCents", privateHostBaseCents);
  }

  const disc = computeDiscountsAndPromo({
    hostBasePriceCents: hostBasePriceCents,
    hostPct: hostPctRequested,
    adminPct: adminPctRequested,
    // Promo is treated as an admin subsidy applied AFTER platform fee (matches current server behavior).
    promoPctRequested: 0
  });

  const pf = computePlatformFeeCentsGross({
    hostBasePriceCents: hostBasePriceCents,
    platformFeePolicy: platformFeePolicy
  });

  const guestDisplayedPriceCents = computeGuestDisplayedPriceCents({
    finalHostChargeCents: disc.finalHostChargeCents,
    platformFeeCentsGross: pf.platformFeeCentsGross
  });

  const acct = computeHostPayoutAndSubsidy({
    hostBasePriceCents: hostBasePriceCents,
    hostPctApplied: disc.hostPctApplied,
    finalHostChargeCents: disc.finalHostChargeCents
  });

  // Invariant: finalHostCharge + baseAdminSubsidy must equal hostPayout.
  const baseAdminSubsidyCents = _requireInt("baseAdminSubsidyCents", _round(Number(acct.adminSubsidyCents) || 0));
  const hostPayoutCents = _requireInt("hostPayoutCents", _round(Number(acct.hostPayoutCents) || 0));
  const finalHostChargeCents = _requireInt("finalHostChargeCents", _round(Number(disc.finalHostChargeCents) || 0));
  if ((finalHostChargeCents + baseAdminSubsidyCents) !== hostPayoutCents) {
    throw new Error("PRICING_INVARIANT_HOSTPAYOUT_MISMATCH");
  }

  // Promo subsidy applies to the guest displayed price (post platform fee).
  const baseForPromoCents = _requireInt("baseForPromoCents", guestDisplayedPriceCents);
  const pctOffCents = (promoPercentOff > 0) ? _round(baseForPromoCents * (promoPercentOff / 100)) : 0;
  const promoOffCents = _requireInt("promoOffCents", _clamp(_round(Math.max(pctOffCents, promoFixedOffCents)), 0, baseForPromoCents));

  const totalCents = _requireInt("totalCents", _round(baseForPromoCents - promoOffCents));
  const adminSubsidyCents = _requireInt("adminSubsidyCents", _round(baseAdminSubsidyCents + promoOffCents));

  const preDiscountCents = _requireInt("preDiscountCents", hostBasePriceCents);
  const discountSource = disc.discountSource != null ? String(disc.discountSource) : "";
  const discountPct = _requireInt("discountPct", _round(Number(disc.priceDiscountPctApplied) || 0));
  const discountMinGuests = _requireInt("discountMinGuests", _round(Number(disc.minGuestsApplied) || 0));

  const description = args.description != null ? String(args.description) : "";

  return {
    unitCents: unitCents,
    guests: guests,
    subtotalCents: rawSubtotalCents,
    hostBasePriceCents: hostBasePriceCents,
    preDiscountCents: preDiscountCents,
    discount: { source: discountSource, percent: discountPct, minGuests: discountMinGuests },
    platformFeeCentsGross: _requireInt("platformFeeCentsGross", _round(Number(pf.platformFeeCentsGross) || 0)),
    promoOffCents: promoOffCents,
    totalCents: totalCents,
    hostPayoutCents: hostPayoutCents,
    adminSubsidyCents: adminSubsidyCents,
    description: description
  };
}

module.exports = {
  computePlatformFeeCentsGross,
  computeDiscountsAndPromo,
  computeGuestDisplayedPriceCents,
  computeHostPayoutAndSubsidy,
  computeBookingPricingSnapshot,
  computeRefundCents
};
