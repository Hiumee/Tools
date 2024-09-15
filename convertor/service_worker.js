// From https://tudip.com/blog-post/how-to-turn-a-website-or-web-application-into-pwa-with-example/
// Cached core static resources 
self.addEventListener("install",e=>{
    e.waitUntil(
      caches.open("static").then(cache=>{
        return cache.addAll([".","./favicon.ico","./favicon16.png","./favicon32.png","./favicon180.png","./favicon192.png","./favicon512.png","./index.js","./style.css"]);
      })
    );
  });
  
  // Fatch resources
  self.addEventListener("fetch",e=>{
    e.respondWith(
      caches.match(e.request).then(response=>{
        return response||fetch(e.request);
      })
    );
  });