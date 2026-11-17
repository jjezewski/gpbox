setInterval(async () => {
  try {
    const s = await (await fetch("/status", { cache: "no-store" })).json();
    if (!s.login) location.href = "/";
  } catch (e) {}
}, 2000);
