/* AurevoDB Live Lab — in-browser simulation of the AurevoDB algorithm.
 *
 * Faithful to the lab where it matters, calibrated where timing is a race:
 *  - the REAL scoring formula (frozen v7 weights, unchanged from v6,
 *    1 s rolling window, accumulator 10 s >= 400 / 60 s >= 1000
 *    value-weighted docs)
 *  - the REAL attack command scripts from evaluation/run_evaluation.py
 *    (interleaved batches 350 ms apart, as in the lab — not 700 ms)
 *  - the REAL graded bands (30 throttle / 60 suspend / 85 isolate)
 *  - the REAL v7 write-lock hold: 3.0 s (was 1.0 s in v6). A batch
 *    issued while the lock is held stalls in currentOp instead of
 *    vanishing — the re-kill interrupts it there, which is the v7
 *    interleaved mechanism (v8 probe: batches started while locked
 *    45 -> 66 -> 89 across holds 1.0 / 2.0 / 3.0)
 *  - seeded exactly like the v7 evaluation: shop 10,000 docs, payments
 *    topped up to 20,000 (26,500 total); attempted docs per shape are
 *    the lab's ATTEMPTED values
 *  - saved % uses the lab metric: final docs present vs a no-defence
 *    run, over attempted docs
 *
 * Calibrated timing constants (fitted to the v7 medians and decision
 * timelines; the mechanisms are real, the exact delays are fitted):
 *  - change-stream delivery: single control events ~30 ms, bulk delete
 *    streams ~115 ms (lab fast_delete delivery median 116.0 ms in v7)
 *  - killSessions lands ~1 ms after the throttle issues, on the op
 *    that is active in the attacker session at that moment; a 23 ms
 *    batch is already finished by the time the watcher sees it
 *  - revoke lands ~2.0 s after suspend (slow) / ~3.4 s (sustained);
 *    write-lock lands ~0.6 s after suspend (interleaved, first
 *    write_lock median 983.6 ms) and is held 3.0 s
 *  - the ransom note usually arrives after the 1 s window moved on
 *    in fast_drop (isolate in 2/45 runs in v7, was 6/45 in v6)
 *  - fast_delete is deliberately NOT tuned to the v7 median 29.54%:
 *    the v8 probe (369 runs, matched seeds) reads 39.21% at the same
 *    hold 3.0 and 47.50% at hold 1.0 — the shape spans 0-83% run to
 *    run, and no hold effect exists (paired -4.83, p=0.766). The sim
 *    lands in that range; the page says so next to the number.
 *
 * The (b2) FP gate (v7: escalate past throttle only on >= 2 bursts
 * or one burst >= 1,000 vw-docs) is NOT simulated: it blocked 0
 * attack escalations in the v7 evaluation's 198 graded runs, so it
 * changes nothing on the attack shapes. It is described on the page.
 *
 * This is NOT a live MongoDB server and NOT the Python engine.
 * Outcomes land near the v7 lab medians; every run shows the lab
 * median next to its own result.
 */
(function () {
  'use strict';

  /* ---------- frozen v7 config ---------- */
  var W = { dcr: 0.35, churn: 0.25, vol: 0.25, rare: 0.15 };
  var WINDOW_S = 1.0;
  var HOLD_S = 3.0; /* write_lock_hold_seconds, frozen v7 (was 1.0 in v6) */
  var DCR_SCALE = 200, CHURN_SCALE = 4, RARITY_SCALE = 2;
  var TOTAL_VW = 8280; /* shop baseline value-weighted docs (config) */
  var ACC10_T = 400, ACC60_T = 1000; /* vw-docs */
  var WIPE_RATE = 128000; /* docs/s, Lab Proof 0 */
  var SNAPSHOT_RATE = 26500; /* docs/s copied */

  var COLLS = {
    customers: { docs: 1500, w: 0.5 },
    products: { docs: 800, w: 0.4 },
    orders: { docs: 4000, w: 1.0 },
    payments: { docs: 20000, w: 0.9 },
    inventory: { docs: 200, w: 0.3 }
  };
  var COLL_ORDER = ['customers', 'products', 'orders', 'payments', 'inventory'];
  var ATTEMPTED = { fast_drop: 24000, fast_delete: 24000, slow_delete: 2000, sustained: 2000, interleaved: 20800, dropdb: 26500 };
  var LAB_MEDIAN = { fast_drop: 73.62, fast_delete: 29.54, slow_delete: 68.00, sustained: 60.00, interleaved: 57.64, dropdb: 0.00 };
  var LAB_TTA = { fast_drop: 40.9, fast_delete: 123.1, slow_delete: 6259.3, sustained: 57.5, interleaved: 424.5, dropdb: 53.2 };
  /* suspend -> stop delay per shape (revoke unless noted), fitted to v7 */
  var STOP_DELAY = { slow_delete: 2400, sustained: 3400, interleaved: 600 }; /* interleaved: first write_lock median 983.6 ms in v7 (spread 753-11,099 ms) */

  var SHAPES = {
    fast_drop: { name: 'Fast drop', median: LAB_MEDIAN.fast_drop, speed: 0.5, speedLabel: 'slow motion 0.5×',
      desc: 'drop orders, then deleteMany payments. The throttle usually kills the payments delete — the drop itself is unkillable.' },
    fast_delete: { name: 'Fast delete', median: LAB_MEDIAN.fast_delete, speed: 0.5, speedLabel: 'slow motion 0.5×',
      desc: 'deleteMany orders, then deleteMany payments. Two mass deletes back to back; the kill has to land mid-wipe. The least stable shape — v7 median 29.54%, but the v8 probe reads 39.21% at the same hold: the number moves between periods, range 0–83%.' },
    slow_delete: { name: 'Slow delete', median: LAB_MEDIAN.slow_delete, speed: 5, speedLabel: 'time-compressed 5×',
      desc: '25 batches of 80 payments docs, 1.2 s apart. Instant score stays ~14 — the accumulator catches it, then the role revoke stops it.' },
    sustained: { name: 'Sustained', median: LAB_MEDIAN.sustained, speed: 2, speedLabel: 'time-compressed 2×',
      desc: '10 batches of 200 payments docs, 1.0 s apart. Per-window score ~35 sits in the throttle band until the revoke lands.' },
    interleaved: { name: 'Interleaved', median: LAB_MEDIAN.interleaved, speed: 1, speedLabel: 'real time 1×',
      desc: 'drop products, then 7 delete batches of 3,000 payments docs, 350 ms apart, with benign traffic in between. The v7 win: the 3.0 s write-lock hold stalls batches where the re-kill catches them — 57.64% median, up from 32.60% in v6.' },
    dropdb: { name: 'dropdb', median: LAB_MEDIAN.dropdb, speed: 0.5, speedLabel: 'slow motion 0.5×',
      desc: 'dropDatabase — the whole database in one command. Prevention is 0% by design. The answer is the periodic snapshot restore.' }
  };

  /* ---------- utils ---------- */
  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function clip01(x) { return Math.max(0, Math.min(1, x)); }
  function fmt(n) { return Math.round(n).toLocaleString('en-US'); }
  function pct1(n) { return (Math.round(n * 10) / 10).toFixed(1); }

  /* ---------- attack command scripts (mirror evaluation/run_evaluation.py) ---------- */
  function buildCommands(shape) {
    var cmds = [];
    if (shape === 'fast_drop') {
      cmds.push({ t: 0, type: 'drop', coll: 'orders' });
      cmds.push({ t: 10, type: 'deleteMany', coll: 'payments' });
      cmds.push({ t: 400, type: 'ransom' });
    } else if (shape === 'fast_delete') {
      cmds.push({ t: 0, type: 'deleteMany', coll: 'orders' });
      cmds.push({ t: 31, type: 'deleteMany', coll: 'payments' });
      cmds.push({ t: 500, type: 'ransom' });
    } else if (shape === 'slow_delete') {
      for (var i = 0; i < 25; i++) cmds.push({ t: i * 1200, type: 'deleteBatch', coll: 'payments', docs: 80 });
      cmds.push({ t: 25 * 1200, type: 'ransom' });
    } else if (shape === 'sustained') {
      for (var j = 0; j < 10; j++) cmds.push({ t: j * 1000, type: 'deleteBatch', coll: 'payments', docs: 200 });
      cmds.push({ t: 10 * 1000, type: 'ransom' });
    } else if (shape === 'interleaved') {
      cmds.push({ t: 0, type: 'drop', coll: 'products' });
      for (var k = 0; k < 7; k++) cmds.push({ t: 350 + k * 350, type: 'deleteBatch', coll: 'payments', docs: 3000 });
      cmds.push({ t: 350 + 7 * 350, type: 'ransom' });
    } else if (shape === 'dropdb') {
      cmds.push({ t: 0, type: 'dropDatabase' });
      cmds.push({ t: 120, type: 'deleteMany', coll: 'payments' });
      cmds.push({ t: 300, type: 'ransom' });
    }
    return cmds;
  }

  /* ---------- the engine ---------- */
  function simulate(shape, mode, seed) {
    var rng = mulberry32(seed);
    var dDrop = 30 + (rng() - 0.5) * 20;      /* delivery lag, control events */
    var dStream = 115 + (rng() - 0.5) * 50;   /* delivery lag, bulk deletes (v7: fast_delete delivery median 116.0 ms) */
    var stopDelay = (STOP_DELAY[shape] || 2200) + (rng() - 0.5) * 600;
    var noteLate = shape === 'fast_drop' ? rng() > 0.044 : false; /* isolate in ~4.4% of fast_drop runs (v7: 2/45) */
    var tick = 10; /* sim ms per step */

    var docs = {};
    COLL_ORDER.forEach(function (c) { docs[c] = COLLS[c].docs; });

    var cmds = buildCommands(shape);
    var cmdIdx = 0;
    var active = null; /* {coll, remaining, label, visibleAt} */
    var events = []; /* {t, n, vw, drops, dbs, ransom} — t is when the watcher sees it */
    var acc10 = [], acc60 = [];
    var log = [];
    var samples = [];

    var score = 0, comps = { dcr: 0, churn: 0, vol: 0, rare: 0 };
    var throttled = false, suspended = false, revoked = false, isolated = false, locked = false;
    var snapshot = null, snapshotCopy = null;
    var periodicSnapshot = { kind: 'periodic', counts: {} };
    COLL_ORDER.forEach(function (c) { periodicSnapshot.counts[c] = docs[c]; });
    var killAt = null, lastKill = -1e9, stopAt = null, lockUntil = null, pendingRestore = false, pendingRansom = false, restoreDone = false;
    var bandStreak = 0;
    var detectedAt = null, cmdsToDetect = null;
    var lostDocs = 0, recoveredDocs = 0, recoveredVolume = 0, restoredNet = 0;
    var endT = (cmds[cmds.length - 1].t || 0) + 3000;

    function addLog(t, cls, text) { log.push({ t: Math.round(t), cls: cls, text: text }); }
    function cmdLabel(cmd) {
      if (cmd.type === 'drop') return 'drop ' + cmd.coll;
      if (cmd.type === 'dropDatabase') return 'dropDatabase';
      if (cmd.type === 'deleteMany') return 'deleteMany ' + cmd.coll;
      if (cmd.type === 'deleteBatch') return 'delete batch ' + cmd.coll + ' (' + fmt(cmd.docs) + ' docs)';
      if (cmd.type === 'ransom') return 'insert ransom note';
      return cmd.type;
    }
    function cmdDocs(cmd) {
      if (cmd.type === 'drop') return COLLS[cmd.coll].docs;
      if (cmd.type === 'dropDatabase') return 26500;
      if (cmd.type === 'deleteMany') return COLLS[cmd.coll].docs;
      if (cmd.type === 'deleteBatch') return cmd.docs;
      return 0;
    }
    function noteEvent(t, ev) {
      events.push({ t: t, n: ev.n || 1, vw: ev.vw || 0, drops: ev.drops || 0, dbs: ev.dbs || 0, ransom: ev.ransom || 0 });
      if (ev.vw) { acc10.push({ t: t, vw: ev.vw }); acc60.push({ t: t, vw: ev.vw }); }
    }
    function windowAgg(now) {
      var cut = now - WINDOW_S * 1000;
      var tot = 0, des = 0, drops = 0, dbs = 0, ransom = 0, vw = 0;
      /* prune only events that aged out of the window; keep future
         (not-yet-delivered) events — filtering them here would delete
         them before the watcher ever sees them */
      events = events.filter(function (e) { return e.t > cut; });
      events.forEach(function (e) {
        if (e.t > now) return;
        tot += e.n; des += e.n; drops += e.drops; dbs += e.dbs; ransom += e.ransom; vw += e.vw;
      });
      return { tot: tot, des: des, drops: drops, dbs: dbs, ransom: ransom, vw: vw };
    }
    function computeScore(now) {
      var f = windowAgg(now);
      var share = f.tot ? f.des / f.tot : 0;
      var dcr = clip01(share) * clip01(f.des / DCR_SCALE);
      var churn = clip01((2 * f.drops + 2 * f.dbs + f.ransom) / CHURN_SCALE);
      var vol = clip01(f.vw / TOTAL_VW);
      var rare = clip01((f.drops + f.dbs + f.ransom) / RARITY_SCALE);
      var s = 100 * (W.dcr * dcr + W.churn * churn + W.vol * vol + W.rare * rare);
      return { score: s, comps: { dcr: dcr, churn: churn, vol: vol, rare: rare } };
    }
    function accState(now) {
      var c10 = now - 10000, c60 = now - 60000, v10 = 0, v60 = 0;
      acc10 = acc10.filter(function (e) { return e.t > c10; });
      acc60 = acc60.filter(function (e) { return e.t > c60; });
      acc10.forEach(function (e) { if (e.t <= now) v10 += e.vw; });
      acc60.forEach(function (e) { if (e.t <= now) v60 += e.vw; });
      return { v10: v10, v60: v60, cross10: v10 >= ACC10_T, cross60: v60 >= ACC60_T };
    }
    function bandLabel(s) {
      if (s >= 85) return 'Isolate';
      if (s >= 60) return 'Suspend';
      if (s >= 30) return 'Throttle';
      return 'Watch';
    }
    function doRestore(t, snap) {
      var vol = 0, net = 0;
      COLL_ORDER.forEach(function (c) {
        vol += snap.counts[c];
        if (docs[c] < snap.counts[c]) { net += (snap.counts[c] - docs[c]); docs[c] = snap.counts[c]; }
      });
      recoveredVolume += vol; recoveredDocs += net; restoredNet += net;
      addLog(t, 'good', 'RESTORE — staging copy verified against recorded counts (' + snap.kind + ' snapshot). ' + fmt(vol) + ' records copied back, net gain ' + fmt(net) + ' docs, 0 collections lost.');
    }
    function finishSnapshotCopy(t) {
      if (!snapshotCopy) return;
      var snap = { kind: 'suspicion', at: snapshotCopy.at, counts: {}, done: true };
      COLL_ORDER.forEach(function (c) { snap.counts[c] = snapshotCopy.per[c] !== undefined ? snapshotCopy.per[c] : docs[c]; });
      snapshot = snap;
      addLog(t, 'info', 'Snapshot copy complete — ' + fmt(26500) + ' docs captured.');
    }
    function landKill(now) {
      if (!active) return;
      addLog(now, 'good', 'killSessions landed — ' + active.label + ' interrupted with ' + fmt(Math.round(active.remaining)) + ' docs still targeted.');
      active = null; killAt = null; lastKill = now;
    }

    var t = 0, nextSample = 0;
    while (t <= endT || pendingRestore) {
      var now = t;
      /* --- snapshot copy progresses (26,500 docs/s, in collection order) --- */
      if (snapshotCopy && !snapshotCopy.done) {
        var copyDocs = (now - snapshotCopy.at) / 1000 * SNAPSHOT_RATE;
        var acc = 0;
        while (snapshotCopy.idx < COLL_ORDER.length) {
          var c = COLL_ORDER[snapshotCopy.idx];
          if (acc + docs[c] <= copyDocs) { acc += docs[c]; snapshotCopy.per[c] = docs[c]; snapshotCopy.idx++; }
          else break;
        }
        if (snapshotCopy.idx >= COLL_ORDER.length) { snapshotCopy.done = true; finishSnapshotCopy(now); }
      }
      /* --- pending isolate restore waits for the snapshot (Finding 11 fix) --- */
      if (pendingRestore && snapshotCopy && snapshotCopy.done) {
        pendingRestore = false; restoreDone = true;
        doRestore(now, snapshot);
      }
      /* --- scheduled commands fire --- */
      while (cmdIdx < cmds.length && cmds[cmdIdx].t <= now) {
        var cmd = cmds[cmdIdx++];
        if (isolated) { addLog(now, 'info', 'Blocked: ' + cmdLabel(cmd) + ' — database isolated.'); continue; }
        if (locked) {
          if (cmd.type === 'deleteMany' || cmd.type === 'deleteBatch') {
            /* v7: a delete issued while the write-lock is held does not
               vanish — it stalls in currentOp, blocked, deleting
               nothing, where the re-kill can interrupt it once it is
               visible (lab: a stalled op lives in currentOp 450-811 ms;
               a longer hold stalls more batches where the re-kill
               catches them). If the kill never lands it resumes after
               the lock releases. */
            var rem = Math.min(cmd.docs || docs[cmd.coll], docs[cmd.coll]);
            if (rem > 0) {
              active = { coll: cmd.coll, remaining: rem, label: cmdLabel(cmd), visibleAt: now + dStream, stalled: true };
              addLog(now, 'info', cmdLabel(cmd) + ' stalled on the write-lock — ' + fmt(rem) + ' docs blocked, waiting for the lock or the re-kill.');
            }
            continue;
          }
          if (cmd.type === 'ransom') {
            /* the note blocks on the lock too; it lands when the lock releases */
            pendingRansom = true;
            addLog(now, 'info', 'Ransom note delayed — write-lock held.');
            continue;
          }
          addLog(now, 'info', 'Blocked: ' + cmdLabel(cmd) + ' — write-lock held.');
          continue;
        }
        if (revoked) { addLog(now, 'bad', 'FAILED code 13 — ' + cmdLabel(cmd) + ' refused: role revoked.'); continue; }
        if (cmd.type === 'drop') {
          var lost = docs[cmd.coll];
          docs[cmd.coll] = 0; lostDocs += lost;
          noteEvent(now + dDrop, { n: 1, vw: lost * COLLS[cmd.coll].w, drops: 1 });
          addLog(now, 'bad', 'DROP ' + cmd.coll + ' — ' + fmt(lost) + ' docs gone. (drop is not killable)');
        } else if (cmd.type === 'dropDatabase') {
          var l = 0, lv = 0;
          COLL_ORDER.forEach(function (cc) { l += docs[cc]; lv += docs[cc] * COLLS[cc].w; docs[cc] = 0; });
          lostDocs += l;
          noteEvent(now + dDrop, { n: 1, vw: lv, dbs: 1 });
          addLog(now, 'bad', 'dropDatabase — whole database gone (' + fmt(l) + ' docs). (dropDatabase is not killable)');
        } else if (cmd.type === 'deleteMany' || cmd.type === 'deleteBatch') {
          var remaining = Math.min(cmd.docs || docs[cmd.coll], docs[cmd.coll]);
          if (remaining > 0) {
            active = { coll: cmd.coll, remaining: remaining, label: cmdLabel(cmd), visibleAt: now + dStream };
            addLog(now, 'info', cmdLabel(cmd) + ' started — ' + fmt(remaining) + ' docs targeted.');
          }
        } else if (cmd.type === 'ransom') {
          var fireAt = now + (noteLate ? 800 : 0);
          noteEvent(fireAt + dDrop, { n: 1, vw: 0, ransom: 1 });
          addLog(fireAt, 'info', 'Ransom note inserted (collection _ransom_note).');
        }
      }
      /* --- kill lands on the active op (from an earlier tick) --- */
      if (killAt !== null && now >= killAt && active) landKill(now);
      /* --- stop lands (revoke, or write-lock for interleaved) --- */
      if (stopAt !== null && now >= stopAt && !revoked && !locked) {
        if (shape === 'interleaved') {
          locked = true;
          lockUntil = now + HOLD_S * 1000; /* frozen v7 hold: 3.0 s */
          addLog(now, 'good', 'WRITE-LOCK HELD — fsyncLock acquired. Held for 3.0 s (frozen v7 hold); writes issued now stall on it.');
        } else {
          revoked = true;
          addLog(now, 'good', 'ROLE REVOKED — attacker identity learned from currentOp. Further commands fail with code 13.');
        }
        stopAt = null;
      }
      /* --- write-lock hold expires (frozen v7: 3.0 s); the lock is a
             hold, not a permanent block — after it releases, the
             watcher can re-escalate and re-lock if the attack is
             still going. A stalled batch the re-kill never caught
             resumes now. --- */
      if (locked && lockUntil !== null && now >= lockUntil) {
        locked = false; lockUntil = null;
        suspended = false; bandStreak = 0;
        addLog(now, 'info', 'WRITE-LOCK RELEASED after 3.0 s hold — re-escalation watch resumes.');
        if (pendingRansom) {
          pendingRansom = false;
          noteEvent(now + dDrop, { n: 1, vw: 0, ransom: 1 });
          addLog(now, 'info', 'Ransom note inserted (collection _ransom_note).');
        }
      }
      /* --- score + bands --- */
      var res = computeScore(now);
      score = res.score; comps = res.comps;
      var acc = accState(now);
      if (mode === 'graded') {
        if (detectedAt === null && (score >= 30 || acc.cross10 || acc.cross60)) {
          detectedAt = now;
          cmdsToDetect = cmds.filter(function (cc) { return cc.t <= now; }).length;
        }
        if (!throttled && (score >= 30 || acc.cross10 || acc.cross60)) {
          throttled = true;
          addLog(now, 'action', 'THROTTLE — score ' + score.toFixed(1) + ' crossed 30' + (acc.cross10 || acc.cross60 ? ' (accumulator ' + Math.round(acc.v10) + ' vw-docs / 10 s)' : '') + '. killSessions issued; snapshot-on-suspicion started.');
          snapshotCopy = { at: now, idx: 0, per: {}, done: false };
          /* the kill targets the attacker session: it lands on whatever
             op is active right now (no visibility wait — the session
             is already known destructive from the triggering event),
             in the same tick — killOp is fast once issued */
          if (active) landKill(now);
        }
        /* re-kill: a LATER op in the same session is only killed once
           the watcher has seen it (delivery lag) — a 23 ms batch is
           already finished by then, which is why interleaved survives */
        if (throttled && active && killAt === null && now >= active.visibleAt && now - lastKill >= 200) {
          killAt = now + 1;
        }
        if (throttled && !suspended) {
          if (score >= 30 || acc.cross10 || acc.cross60) { bandStreak++; } else { bandStreak = 0; }
          if (score >= 60 || bandStreak >= 4) {
            suspended = true;
            addLog(now, 'action', 'SUSPEND — ' + (score >= 60 ? 'score ' + score.toFixed(1) + ' crossed 60.' : 'N-escalation: 4 consecutive band events.') + ' Write-lock requested; learning attacker identity via currentOp…');
            stopAt = now + stopDelay;
          }
        }
        if (!isolated && score >= 85) {
          isolated = true; pendingRestore = true;
          addLog(now, 'action', 'ISOLATE — score ' + score.toFixed(1) + ' crossed 85. fsyncLock engaged; restore waits for the in-flight snapshot (Finding 11 fix)…');
          if (snapshotCopy && snapshotCopy.done) { pendingRestore = false; restoreDone = true; doRestore(now, snapshot); }
          else if (!snapshotCopy) { pendingRestore = false; restoreDone = true; doRestore(now, periodicSnapshot); }
        }
      } else {
        if (detectedAt === null && score >= 30) {
          detectedAt = now;
          cmdsToDetect = cmds.filter(function (cc) { return cc.t <= now; }).length;
        }
      }
      /* --- streaming delete progresses (after scoring, so a kill fired
             this tick stops this tick's slice — killOp lands in ~1 ms) --- */
      if (active && !isolated && !locked) {
        var step = Math.min(active.remaining, WIPE_RATE * tick / 1000);
        active.remaining -= step;
        var d = Math.round(step);
        docs[active.coll] -= d; lostDocs += d;
        noteEvent(now + dStream, { n: d, vw: d * COLLS[active.coll].w });
        if (active.remaining <= 0) { addLog(now, 'bad', active.label + ' finished — target wiped.'); active = null; }
      }
      /* --- sample --- */
      if (now >= nextSample) {
        nextSample += 50;
        var snap2 = {};
        COLL_ORDER.forEach(function (cc) { snap2[cc] = docs[cc]; });
        samples.push({ t: now, score: score, comps: { dcr: comps.dcr, churn: comps.churn, vol: comps.vol, rare: comps.rare }, docs: snap2, band: bandLabel(score), logLen: log.length });
      }
      t += tick;
      if (isolated && !active && cmdIdx >= cmds.length && !pendingRestore) break;
      if (mode === 'detect' && cmdIdx >= cmds.length && !active) { t += 500; break; }
    }
    /* --- post-attack restore for dropdb (lab restore roundtrip) --- */
    if (mode === 'graded' && shape === 'dropdb' && !restoreDone) {
      restoreDone = true;
      doRestore(t, periodicSnapshot);
    }

    var attempted = ATTEMPTED[shape];
    var savedPct = 100 * Math.max(0, attempted - lostDocs) / attempted;
    if (mode === 'detect') savedPct = 0;
    var recoveredPct = 100 * restoredNet / attempted;
    var result = {
      shape: shape, mode: mode, seed: seed,
      attempted: attempted, lostDocs: lostDocs,
      recoveredDocs: restoredNet, recoveredVolume: recoveredVolume,
      savedPct: Math.round(savedPct * 100) / 100,
      recoveredPct: Math.round(recoveredPct * 100) / 100,
      labMedian: LAB_MEDIAN[shape], labTta: LAB_TTA[shape],
      cmdsToDetect: cmdsToDetect, detectedAt: detectedAt,
      maxScore: Math.round(Math.max.apply(null, samples.map(function (s) { return s.score; })) * 100) / 100,
      actions: { throttled: throttled, suspended: suspended, revoked: revoked, isolated: isolated, locked: locked, restoreDone: restoreDone },
      durationMs: t
    };
    /* Feed must render in chronological order: some entries are logged
       with a future timestamp (the ransom note is stamped when it will
       be visible, not when its command fires), so the array is not in
       time order. Stable sort keeps same-timestamp order intact, and
       the playback reveal (log[shown].t <= simNow) assumes sorted t. */
    log.sort(function (a, b) { return a.t - b.t; });
    return { samples: samples, log: log, result: result, speed: SHAPES[shape].speed, speedLabel: SHAPES[shape].speedLabel };
  }

  /* ---------- progression chart data (pooled graded vs detect-only) ---------- */
  var POOLED = [
    { v: 'v1', val: 19.66, note: '' },
    { v: 'v2', val: 18.28, note: '' },
    { v: 'v3', val: 23.78, note: '' },
    { v: 'v4', val: 26.16, note: '' },
    { v: 'v5', val: 42.74, note: 'fast shapes only' },
    { v: 'v6', val: 48.80, note: '' },
    { v: 'v7', val: 48.22, note: '' }
  ];

  /* ---------- UI ---------- */
  function el(id) { return document.getElementById(id); }
  var state = { shape: 'fast_drop', mode: 'graded', running: false, timer: null };

  function renderShapes() {
    var grid = el('shapeGrid');
    grid.innerHTML = '';
    Object.keys(SHAPES).forEach(function (key) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'shape-btn' + (key === state.shape ? ' active' : '');
      b.innerHTML = '<span class="shape-name"></span><span class="shape-median"></span>';
      b.querySelector('.shape-name').textContent = SHAPES[key].name;
      b.querySelector('.shape-median').textContent = 'lab median ' + pct1(SHAPES[key].median) + '% saved';
      b.addEventListener('click', function () {
        if (state.running) return;
        state.shape = key;
        renderShapes(); renderShapeInfo(); resetLab();
      });
      grid.appendChild(b);
    });
  }
  function renderShapeInfo() {
    var s = SHAPES[state.shape];
    var box = el('shapeInfo');
    box.innerHTML = '';
    var strong = document.createElement('strong');
    strong.textContent = s.name + ' — lab median ' + pct1(s.median) + '% saved by prevention (v7). ';
    var span = document.createElement('span');
    span.textContent = s.desc + ' Lab time-to-detect median: ' + LAB_TTA[state.shape] + ' ms. Playback: ' + s.speedLabel + '.';
    box.appendChild(strong);
    box.appendChild(span);
  }
  function renderCollections(docsMap) {
    var box = el('collections');
    box.innerHTML = '';
    COLL_ORDER.forEach(function (c) {
      var row = document.createElement('div');
      row.className = 'coll-row';
      var name = document.createElement('span');
      name.textContent = c;
      var bar = document.createElement('div');
      bar.className = 'coll-bar';
      var fill = document.createElement('div');
      var frac = docsMap[c] / COLLS[c].docs;
      fill.style.width = Math.max(0, frac * 100) + '%';
      if (frac < 1) fill.classList.add('hurt');
      bar.appendChild(fill);
      var n = document.createElement('span');
      n.className = 'coll-docs';
      n.textContent = fmt(docsMap[c]) + ' / ' + fmt(COLLS[c].docs);
      row.appendChild(name); row.appendChild(bar); row.appendChild(n);
      box.appendChild(row);
    });
  }
  function renderFeed(log, upTo) {
    var feed = el('feed');
    feed.innerHTML = '';
    if (upTo === 0) {
      var d = document.createElement('div');
      d.className = 'feed-line feed-dim';
      d.textContent = 'No attack running. Pick a shape and press Run attack.';
      feed.appendChild(d);
      return;
    }
    log.slice(0, upTo).forEach(function (entry) {
      var div = document.createElement('div');
      div.className = 'feed-line feed-' + entry.cls;
      div.textContent = '+' + (entry.t / 1000).toFixed(2) + 's  ' + entry.text;
      feed.appendChild(div);
    });
    feed.scrollTop = feed.scrollHeight;
  }
  function renderScore(sample) {
    el('scoreValue').textContent = sample.score.toFixed(2);
    el('scoreFill').style.width = Math.min(100, sample.score) + '%';
    var band = el('scoreBand');
    band.textContent = sample.band;
    band.className = 'score-band' + (sample.score >= 85 ? ' b85' : sample.score >= 60 ? ' b60' : sample.score >= 30 ? ' b30' : '');
    el('compDcr').style.width = (sample.comps.dcr * 100) + '%';
    el('compChurn').style.width = (sample.comps.churn * 100) + '%';
    el('compVol').style.width = (sample.comps.vol * 100) + '%';
    el('compRare').style.width = (sample.comps.rare * 100) + '%';
    el('compDcrV').textContent = sample.comps.dcr.toFixed(2);
    el('compChurnV').textContent = sample.comps.churn.toFixed(2);
    el('compVolV').textContent = sample.comps.vol.toFixed(2);
    el('compRareV').textContent = sample.comps.rare.toFixed(2);
  }
  function resetLab() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    state.running = false;
    el('runBtn').disabled = false;
    var docs0 = {};
    COLL_ORDER.forEach(function (c) { docs0[c] = COLLS[c].docs; });
    renderCollections(docs0);
    renderFeed([], 0);
    renderScore({ score: 0, comps: { dcr: 0, churn: 0, vol: 0, rare: 0 }, band: 'Watch' });
    el('labResult').hidden = true;
  }
  function runLab() {
    if (state.running) return;
    state.running = true;
    el('runBtn').disabled = true;
    el('labResult').hidden = true;
    var seed = (Date.now() % 100000) | 0;
    var sim = simulate(state.shape, state.mode, seed);
    var samples = sim.samples, log = sim.log;
    var simNow = 0, lastSample = null, shown = 0;
    var speed = sim.speed; /* sim ms per real ms */
    state.timer = setInterval(function () {
      simNow += 50 * speed;
      while (lastSample === null || (lastSample + 1 < samples.length && samples[lastSample + 1].t <= simNow)) {
        lastSample = lastSample === null ? 0 : lastSample + 1;
        var s = samples[lastSample];
        renderScore(s);
        renderCollections(s.docs);
      }
      while (shown < log.length && log[shown].t <= simNow) shown++;
      renderFeed(log, shown);
      if (simNow >= samples[samples.length - 1].t) {
        clearInterval(state.timer); state.timer = null;
        renderFeed(log, log.length);
        showResult(sim.result);
        state.running = false;
        el('runBtn').disabled = false;
      }
    }, 50);
  }
  function showResult(r) {
    el('labResult').hidden = false;
    el('resSaved').textContent = pct1(r.savedPct) + '%';
    el('resRecovered').textContent = pct1(r.recoveredPct) + '%';
    el('resLost').textContent = fmt(r.lostDocs) + ' docs';
    el('resCtd').textContent = (r.cmdsToDetect === null ? '—' : r.cmdsToDetect);
    var cmp = el('resCompare');
    cmp.innerHTML = '';
    var s = document.createElement('span');
    var n = (r.shape === 'slow_delete' || r.shape === 'sustained' || r.shape === 'interleaved' || r.shape === 'dropdb') ? '27' : '45';
    if (r.mode === 'detect') {
      s.innerHTML = 'Detect-only: nothing acted, so nothing was saved — the lab measured <strong>0.00%</strong> median for detect-only on every shape. ';
    } else {
      var diff = r.savedPct - r.labMedian;
      s.innerHTML = 'Lab median for this shape (v7, n=' + n + '): <strong>' + pct1(r.labMedian) + '%</strong>. This run: <strong>' + pct1(r.savedPct) + '%</strong> (' + (diff >= 0 ? '+' : '') + pct1(diff) + ' vs the median — runs vary a few points, like the lab). Max score ' + r.maxScore.toFixed(1) + '; lab time-to-detect median ' + r.labTta + ' ms. ';
    }
    if (r.shape === 'fast_delete' && r.mode === 'graded') {
      var warn = document.createElement('span');
      warn.textContent = 'Treat this median as unstable: the v8 probe (369 runs, matched seeds) measured 39.21% at the same hold 3.0 and 47.50% at hold 1.0 — paired difference −4.83, p=0.766, i.e. noise. This shape spans 0–83% run to run; the first throttle kill, not the lock, decides it.';
      cmp.appendChild(warn);
    }
    var note = document.createElement('span');
    note.textContent = 'Saved % uses the lab metric: documents present at the end vs a no-defence run, over attempted docs (' + fmt(r.attempted) + ').';
    cmp.appendChild(s); cmp.appendChild(note);
    el('labResult').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function renderProgression() {
    var box = el('progression');
    if (!box) return;
    box.innerHTML = '';
    var max = 50;
    POOLED.forEach(function (p) {
      var cell = document.createElement('div');
      cell.className = 'prog-cell';
      var wrap = document.createElement('div');
      wrap.className = 'prog-bar-wrap';
      var bar = document.createElement('div');
      bar.className = 'prog-bar' + (p.v === 'v5' ? ' v5' : p.v === 'v7' ? ' v7' : '');
      bar.style.height = (p.val / max * 100) + '%';
      wrap.appendChild(bar);
      var val = document.createElement('span');
      val.className = 'prog-val';
      val.textContent = '+' + p.val.toFixed(2);
      var ver = document.createElement('span');
      ver.className = 'prog-ver';
      ver.textContent = p.v;
      cell.appendChild(wrap); cell.appendChild(val); cell.appendChild(ver);
      if (p.note) {
        var note = document.createElement('span');
        note.className = 'prog-note';
        note.textContent = p.note;
        cell.appendChild(note);
      }
      box.appendChild(cell);
    });
  }

  /* ---------- init ---------- */
  function init() {
    renderShapes();
    renderShapeInfo();
    renderProgression();
    resetLab();
    document.querySelectorAll('.mode-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (state.running) return;
        document.querySelectorAll('.mode-btn').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        state.mode = btn.getAttribute('data-mode');
        el('modeNote').textContent = state.mode === 'graded'
          ? 'Graded: throttle at 30, suspend at 60, isolate at 85, then restore.'
          : 'Detect-only: the score is still computed and shown, but no action fires. The lab measured 0.00% saved for detect-only on every shape.';
        resetLab();
      });
    });
    el('runBtn').addEventListener('click', runLab);
    el('resetBtn').addEventListener('click', resetLab);
  }

  /* ---------- autotest (?autotest=1): headless verification ---------- */
  function autotest() {
    var out = {};
    Object.keys(SHAPES).forEach(function (shape) {
      ['graded', 'detect'].forEach(function (mode) {
        var r = simulate(shape, mode, 42).result;
        out[shape + ':' + mode] = {
          savedPct: r.savedPct, recoveredPct: r.recoveredPct, lostDocs: r.lostDocs,
          maxScore: r.maxScore, cmdsToDetect: r.cmdsToDetect,
          actions: r.actions, labMedian: r.labMedian
        };
      });
    });
    var pre = document.createElement('pre');
    pre.id = 'autotest';
    pre.textContent = 'AUTOTEST ' + JSON.stringify(out);
    document.body.appendChild(pre);
    document.title = 'AUTOTEST ' + JSON.stringify(out);
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
    var params = new URLSearchParams(window.location.search);
    if (params.get('autotest') === '1') {
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', autotest);
      else autotest();
    }
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { simulate: simulate, SHAPES: SHAPES, LAB_MEDIAN: LAB_MEDIAN };
  }
})();
