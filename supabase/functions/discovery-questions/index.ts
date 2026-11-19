// Supabase Edge Function: discovery-questions
// Deploy with: supabase functions deploy discovery-questions
// Configure OPENAI_API_KEY as an Edge Function secret. Never expose it to browser code.
const cors={"Access-Control-Allow-Origin":"https://chat.tichor.com","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS"};
Deno.serve(async(req)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 const respond=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{...cors,"Content-Type":"application/json","Cache-Control":"no-store"}});
 if(req.method!=="POST")return respond({error:"Method not allowed"},405);
 try{
  const auth=req.headers.get("authorization")||"";
  if(!auth.startsWith("Bearer "))return respond({error:"Sign in to generate AI questions."},401);
  const url=Deno.env.get("SUPABASE_URL"),anon=Deno.env.get("SUPABASE_ANON_KEY");
  if(!url||!anon)return respond({error:"Server authentication is not configured."},503);
  const identity=await fetch(url+"/auth/v1/user",{headers:{authorization:auth,apikey:anon}});
  if(!identity.ok)return respond({error:"Session expired. Sign in again."},401);
  const user=await identity.json();if(!user?.id)return respond({error:"Authentication required."},401);
  const body=await req.json().catch(()=>({}));
  const topics=["dna","space","heart","mixed"],levels=["easy","medium","hard","mixed"];
  const topic=topics.includes(body.topic)?body.topic:"mixed",difficulty=levels.includes(body.difficulty)?body.difficulty:"mixed";
  const avoid=Array.isArray(body.avoid)?body.avoid.slice(-8).filter(x=>typeof x==="string").map(x=>x.slice(0,160)):[];
  const key=Deno.env.get("OPENAI_API_KEY");if(!key)return respond({error:"AI generation is not enabled by the administrator."},503);
  const prompt="Generate exactly ONE scientifically accurate multiple-choice question for an educational quiz. Topic: "+topic+" (dna=genetics, space=astronomy, heart=human physiology, mixed=any of these). Difficulty: "+difficulty+". Avoid repeating these recent questions: "+JSON.stringify(avoid)+". Include a clear factual explanation. Return ONLY a JSON object with string keys topic, level, prompt, answer, why and an array wrong of exactly three distinct plausible incorrect answers. No markdown. All choices must be distinct. Keep questions accessible, not medical advice.";
  const upstream=await fetch("https://api.openai.com/v1/chat/completions",{method:"POST",headers:{"Authorization":"Bearer "+key,"Content-Type":"application/json"},body:JSON.stringify({model:Deno.env.get("OPENAI_MODEL")||"gpt-4o-mini",temperature:0.8,response_format:{type:"json_object"},messages:[{role:"system",content:"You are a rigorous science educator. Produce accurate, self-contained educational quiz items as JSON."},{role:"user",content:prompt}],max_tokens:500})});
  if(!upstream.ok)return respond({error:"AI provider is temporarily unavailable."},502);
  const data=await upstream.json();let q;try{q=JSON.parse(data.choices?.[0]?.message?.content||"")}catch{return respond({error:"Invalid AI response. Try again."},502)}
  if(!q||!["dna","space","heart"].includes(q.topic)||!["easy","medium","hard"].includes(q.level)||!["prompt","answer","why"].every(k=>typeof q[k]==="string"&&q[k].length>3&&q[k].length<1000)||!Array.isArray(q.wrong)||q.wrong.length!==3||!q.wrong.every(x=>typeof x==="string"&&x.length>0&&x.length<300)||new Set([q.answer,...q.wrong]).size!==4)return respond({error:"AI generated an invalid question. Try again."},502);
  return respond({question:{topic:q.topic,level:q.level,prompt:q.prompt,answer:q.answer,wrong:q.wrong,why:q.why}});
 }catch{return respond({error:"Unable to generate question right now."},500)}
});