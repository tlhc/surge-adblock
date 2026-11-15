// /ws/shield/scene/recommend carries search history beside promo fields.
// Drop search-box shading words and the default tools-recommend list only.
try {
  const raw = $response && $response.body;
  const obj = JSON.parse(raw);
  const data = obj && obj.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    $done({});
  } else {
    let changed = false;
    if (Object.prototype.hasOwnProperty.call(data, "shadingWords")) {
      delete data.shadingWords;
      changed = true;
    }
    const tools = data.toolsRecommend && data.toolsRecommend.data;
    if (tools && typeof tools === "object" && Array.isArray(tools.default) && tools.default.length) {
      tools.default = [];
      changed = true;
    }
    $done(changed ? { body: JSON.stringify(obj) } : {});
  }
} catch (e) {
  $done({});
}
