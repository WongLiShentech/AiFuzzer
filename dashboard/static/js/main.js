// Dashboard front-end. Submits the analyze form to the Flask backend and shows
// the JSON report. Comparison view is populated once benchmark results exist.

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("analyze-form");
  const result = document.getElementById("result");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    result.textContent = "Analyzing…";
    const res = await fetch("/analyze", { method: "POST", body: new FormData(form) });
    const data = await res.json();
    result.textContent = data.ok
      ? JSON.stringify(data.report, null, 2)
      : `Error: ${data.error}`;
  });
});
