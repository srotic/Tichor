'use strict';
/* The supplementary CARS collection consists of newly written conceptual essays and
   source-linked reasoning items, not official AAMC materials. */
window.TICHOR_CARS_EXAMS=window.TICHOR_CARS_EXAMS||{};
window.tcRegisterCarsExam=function(number,entries){
 if(!Number.isInteger(number)||number<2||number>10||!Array.isArray(entries)||entries.length!==9)throw Error('Invalid CARS exam set');
 const paragraphs=s=>[
  s.open+' '+s.thesis+' To appreciate the stakes, one must ask not only what a practice accomplishes, but what it excludes from consideration and which consequences are counted as success.',
  s.orthodox+' Those who favor this view are not necessarily indifferent to its shortcomings. They may have observed a genuine difficulty and fashioned a workable response. Yet the usefulness of a response within a limited setting does not establish its adequacy as a general principle. ',
  s.example+' An observer who attends only to the announced goal may miss the means by which that goal was pursued, the people who bear its costs, or the features that become visible only when the practice is considered from another position.',
  s.limitation+' It would be equally unhelpful, however, to mistake this criticism for a demand that the older approach be abandoned in every situation. The problem is not that a method has limits; every method does. The problem begins when those limits are forgotten or treated as evidence that alternative questions do not deserve a hearing. A responsible account must preserve the earlier approach’s real achievements while explaining what it cannot do.',
  s.alternative+' This proposal does not promise to remove judgment from the field. It makes judgment more explicit, and therefore more open to challenge.  The gain is a form of accountability rather than an imagined escape from disagreement.',
  s.implication+' '+s.boundary+' What ultimately matters is not whether a system presents itself as coherent, modern or impartial, but whether it can acknowledge contrary evidence and explain the criteria by which it decides. A conclusion that survives such examination may be less tidy than the first account, yet it is more deserving of confidence. This is a discipline of interpretation, not an invitation to indecision.'
 ];
 const makeOptions=(correct,wrong,offset)=>{const all=[correct,...wrong];const rot=offset%4;const choices=all.slice(rot).concat(all.slice(0,rot));return [choices,choices.indexOf(correct)]};
 const generated=entries.map((s,passageIndex)=>{
  if(!s||['title','discipline'].some(k=>typeof s[k]!=='string'||!s[k].trim())||['open','thesis','orthodox','example','limitation','alternative','implication','boundary','application'].some(k=>typeof s[k]!=='string'||s[k].trim().length<20))throw Error('Missing substantive passage content in exam '+number);
  const ps=paragraphs(s),q=[];
  const add=(stem,right,wrong,category,why)=>{
   const [options,answer]=makeOptions(right,wrong,(passageIndex+q.length+number)%4);
   q.push([stem,options,answer,category,why]);
  };
  add('Which statement most accurately captures the author’s central argument?',
   s.thesis,[s.orthodox,'No interpretation can be more defensible than any other.','The familiar approach must be rejected in every possible circumstance.'],'Comprehension','The thesis distinguishes the author’s qualified proposal from the conventional view and from more sweeping extremes.');
  add('The author’s treatment of the conventional approach is best described as:',
   'It acknowledges practical merits while questioning its claim to general sufficiency.',
   ['It rejects the approach as knowingly dishonest in all cases.','It accepts the approach as a complete explanation requiring no revision.','It treats the approach as irrelevant to the issue under discussion.'],'Comprehension','The second and fourth paragraphs recognize achievements without accepting an unlimited claim.');
  add('The principal function of the specific example in the third paragraph is to:',
   'Reveal a tension that a general account tends to overlook.',
   ['Establish that the proposed alternative is always successful.','Prove the conventional approach has never worked.','Replace the author’s argument with an unrelated historical anecdote.'],'Within the Text','The example illustrates the limits of the broad claim, rather than serving as decisive proof of an extreme conclusion.');
  add('Which assumption is most important to the author’s proposed alternative?',
   'Exposing the reasons behind decisions can make them more accountable to criticism.',
   ['All participants necessarily hold identical values.','Technical efficiency by itself determines whether a choice is justified.','Uncertainty makes reasoned evaluation impossible.'],'Within the Text','The fifth paragraph’s case rests on open criteria that can be questioned and revised.');
  add(s.application+' Which response is most consistent with the author’s reasoning?',
   'Examine the stated purpose and affected perspectives before judging the new case.',
   ['Apply the conventional rule automatically without considering context.','Assume an alternative is correct merely because it is unfamiliar.','Treat disagreement as proof that no evidence can matter.'],'Beyond the Text','The author urges contextual and evidence-based judgment rather than automatic acceptance or rejection.');
  if(passageIndex!==8)add('Which finding would most directly challenge the author’s preferred account?',
   'Showing that greater transparency systematically worsens evaluation even when evidence and circumstances are comparable.',
   ['Showing that people sometimes disagree over priorities.','Showing that the conventional method succeeds in at least one context.','Showing that judgments require selecting among imperfect criteria.'],'Beyond the Text','The preferred account depends on transparent, revisable judgment improving reason-giving; disagreement and partial success of older methods do not refute it.');
  return {title:s.title,discipline:s.discipline,text:ps.join('\n\n'),q,original:true};
 });
 if(generated.reduce((n,p)=>n+p.q.length,0)!==53)throw Error('Exam must contain exactly 53 questions');
 window.TICHOR_CARS_EXAMS[number-1]=generated;
};

window.tcMakeCarsSeed=function(title,discipline,subject,convention,caseStudy,critique,reform,tradeoff,application){
 const stem='The disagreement about '+subject+' illustrates a broader problem:';
 return {
 title,discipline,
 open:stem+' different people may describe the same arrangement as an achievement or as an obstacle depending on the question they are asking.',
 thesis:'The most defensible reading of '+subject+' requires acknowledging '+critique+' while taking seriously '+reform,
 orthodox:'A familiar defense holds that '+convention+' Its practical appeal should not be underestimated, since predictable rules and recognizable standards often make cooperation possible.',
 example:'Consider the following case: '+caseStudy+' The example forces a distinction between what an institution claims to achieve and what participants actually experience.',
 limitation:'Even critics must admit that '+tradeoff+' This difficulty complicates any effortless celebration of reform and makes the preferred approach vulnerable to its own blind spots.',
 alternative:'A different response would be to '+reform+' Such a change would demand careful explanation of the criteria used to decide between competing values.',
 implication:'If this proposal were taken seriously, judgments about '+subject+' would need to draw on more than a single headline measure or familiar institutional story.',
 boundary:'The point is not to dismiss the insight that '+convention+' but to specify when that insight stops answering the question at issue.',
 application:'Imagine a related setting in which '+application+'.'
 };
};
