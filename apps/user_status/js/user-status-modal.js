(window.webpackJsonpUserStatus=window.webpackJsonpUserStatus||[]).push([[2],{365:function(t,e,s){var a=s(377);"string"==typeof a&&(a=[[t.i,a,""]]),a.locals&&(t.exports=a.locals);(0,s(259).default)("174642e6",a,!0,{})},366:function(t,e,s){var a=s(379);"string"==typeof a&&(a=[[t.i,a,""]]),a.locals&&(t.exports=a.locals);(0,s(259).default)("9bd18a2a",a,!0,{})},367:function(t,e,s){var a=s(381);"string"==typeof a&&(a=[[t.i,a,""]]),a.locals&&(t.exports=a.locals);(0,s(259).default)("6fa59d7a",a,!0,{})},368:function(t,e,s){var a=s(394);"string"==typeof a&&(a=[[t.i,a,""]]),a.locals&&(t.exports=a.locals);(0,s(259).default)("69246a14",a,!0,{})},369:function(t,e,s){var a=s(396);"string"==typeof a&&(a=[[t.i,a,""]]),a.locals&&(t.exports=a.locals);(0,s(259).default)("4bbc091f",a,!0,{})},370:function(t,e,s){var a=s(398);"string"==typeof a&&(a=[[t.i,a,""]]),a.locals&&(t.exports=a.locals);(0,s(259).default)("bc8ebcbc",a,!0,{})},376:function(t,e,s){"use strict";var a=s(365);s.n(a).a},377:function(t,e,s){(e=s(258)(!1)).push([t.i,".predefined-status[data-v-2af0cabf]{display:flex;flex-wrap:nowrap;justify-content:flex-start;flex-basis:100%;border-radius:var(--border-radius);align-items:center;min-height:44px}.predefined-status[data-v-2af0cabf]:hover,.predefined-status[data-v-2af0cabf]:focus{background-color:var(--color-background-hover)}.predefined-status__icon[data-v-2af0cabf]{flex-basis:40px;text-align:center}.predefined-status__message[data-v-2af0cabf]{font-weight:bold;padding:0 6px}.predefined-status__clear-at[data-v-2af0cabf]{opacity:.7}.predefined-status__clear-at[data-v-2af0cabf]::before{content:' - '}\n",""]),t.exports=e},378:function(t,e,s){"use strict";var a=s(366);s.n(a).a},379:function(t,e,s){(e=s(258)(!1)).push([t.i,".predefined-statuses-list[data-v-3b99f880]{display:flex;flex-direction:column;margin-bottom:10px}\n",""]),t.exports=e},380:function(t,e,s){"use strict";var a=s(367);s.n(a).a},381:function(t,e,s){(e=s(258)(!1)).push([t.i,".custom-input__form[data-v-67479d68]{flex-grow:1}.custom-input__form input[data-v-67479d68]{width:100%;border-radius:0 var(--border-radius) var(--border-radius) 0}\n",""]),t.exports=e},393:function(t,e,s){"use strict";var a=s(368);s.n(a).a},394:function(t,e,s){(e=s(258)(!1)).push([t.i,".clear-at-select[data-v-44cd4ace]{display:flex;margin-bottom:10px;align-items:center}.clear-at-select__label[data-v-44cd4ace]{margin-right:10px}.clear-at-select .multiselect[data-v-44cd4ace]{flex-grow:1}\n",""]),t.exports=e},395:function(t,e,s){"use strict";var a=s(369);s.n(a).a},396:function(t,e,s){(e=s(258)(!1)).push([t.i,".user-status-online-select__input[data-v-24baf5da]{position:absolute;top:auto;left:-10000px;overflow:hidden;width:1px;height:1px}.user-status-online-select__label[data-v-24baf5da]{display:block;margin:8px;padding:8px;padding-left:40px;border:2px solid var(--color-main-background);border-radius:var(--border-radius-large);background-color:var(--color-background-hover);background-position:8px center;background-size:24px}.user-status-online-select__input:checked+.user-status-online-select__label[data-v-24baf5da],.user-status-online-select__input:focus+.user-status-online-select__label[data-v-24baf5da],.user-status-online-select__label[data-v-24baf5da]:hover{border-color:var(--color-primary)}\n",""]),t.exports=e},397:function(t,e,s){"use strict";var a=s(370);s.n(a).a},398:function(t,e,s){(e=s(258)(!1)).push([t.i,".set-status-modal[data-v-710897d4]{min-width:500px;min-height:200px;padding:8px 20px 20px 20px;max-height:70vh;overflow:auto}.set-status-modal__header[data-v-710897d4]{text-align:center;font-weight:bold}.set-status-modal__online-status[data-v-710897d4]{display:grid;margin-bottom:40px;grid-template-columns:1fr 1fr}.set-status-modal__online-status .subline[data-v-710897d4]{display:block}.set-status-modal__custom-input[data-v-710897d4]{display:flex;width:100%;margin-bottom:10px}.set-status-modal__custom-input .custom-input__emoji-button[data-v-710897d4]{flex-basis:40px;flex-grow:0;width:40px;height:34px;margin-right:0;border-right:none;border-radius:var(--border-radius) 0 0 var(--border-radius)}.set-status-modal .status-buttons[data-v-710897d4]{display:flex}.set-status-modal .status-buttons button[data-v-710897d4]{flex-basis:50%}\n",""]),t.exports=e},399:function(t,e,s){"use strict";s.r(e);var a=s(326),n=s(371),r=s.n(n),i=s(374),u=s.n(i),l=s(238),o=s(325),c=s(79),d=s.n(c),p=s(327),f=function(t){if(null===t)return Object(l.translate)("user_status","Don't clear");if("end-of"===t.type)switch(t.time){case"day":return Object(l.translate)("user_status","Today");case"week":return Object(l.translate)("user_status","This week");default:return null}if("period"===t.type)return d.a.duration(1e3*t.time).humanize();if("_time"===t.type){var e=d()(Object(p.a)()),s=d()(t.time,"X");return d.a.duration(e.diff(s)).humanize()}return null},b={name:"PredefinedStatus",filters:{clearAtFilter:f},props:{messageId:{type:String,required:!0},icon:{type:String,required:!0},message:{type:String,required:!0},clearAt:{type:Object,required:!1,default:null}},methods:{select:function(){this.$emit("select")}}},m=(s(376),s(80)),h=Object(m.a)(b,(function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",{staticClass:"predefined-status",attrs:{"tabindex":"0"},on:{"keyup":[function(e){return!e.type.indexOf("key")&&t._k(e.keyCode,"enter",13,e.key,"Enter")?null:t.select(e)},function(e){return!e.type.indexOf("key")&&t._k(e.keyCode,"space",32,e.key,[" ","Spacebar"])?null:t.select(e)}],"click":t.select}},[s("span",{staticClass:"predefined-status__icon"},[t._v("\n\t\t"+t._s(t.icon)+"\n\t")]),t._v(" "),s("span",{staticClass:"predefined-status__message"},[t._v("\n\t\t"+t._s(t.message)+"\n\t")]),t._v(" "),s("span",{staticClass:"predefined-status__clear-at"},[t._v("\n\t\t"+t._s(t._f("clearAtFilter")(t.clearAt))+"\n\t")])])}),[],!1,null,"2af0cabf",null).exports,_=s(235);function v(t,e){var s=Object.keys(t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(t);e&&(a=a.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),s.push.apply(s,a)}return s}function g(t){for(var e=1;e<arguments.length;e++){var s=null!=arguments[e]?arguments[e]:{};e%2?v(Object(s),!0).forEach((function(e){y(t,e,s[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(s)):v(Object(s)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(s,e))}))}return t}function y(t,e,s){return e in t?Object.defineProperty(t,e,{value:s,enumerable:!0,configurable:!0,writable:!0}):t[e]=s,t}var x={name:"PredefinedStatusesList",components:{PredefinedStatus:h},computed:g(g({},Object(_.b)({predefinedStatuses:function(t){return t.predefinedStatuses.predefinedStatuses}})),{},{hasLoaded:function(){return this.predefinedStatuses.length>0}}),mounted:function(){this.$store.dispatch("loadAllPredefinedStatuses")},methods:{selectStatus:function(t){this.$emit("selectStatus",t)}}},S=(s(378),Object(m.a)(x,(function(){var t=this,e=t.$createElement,s=t._self._c||e;return t.hasLoaded?s("div",{staticClass:"predefined-statuses-list"},t._l(t.predefinedStatuses,(function(e){return s("PredefinedStatus",{key:e.id,attrs:{"message-id":e.id,"icon":e.icon,"message":e.message,"clear-at":e.clearAt},on:{"select":function(s){return t.selectStatus(e)}}})})),1):s("div",{staticClass:"predefined-statuses-list"},[s("div",{staticClass:"icon icon-loading-small"})])}),[],!1,null,"3b99f880",null).exports),O={name:"CustomMessageInput",props:{message:{type:String,required:!0,default:function(){return""}}},methods:{change:function(t){this.$emit("change",t.target.value)}}},j=(s(380),Object(m.a)(O,(function(){var t=this.$createElement,e=this._self._c||t;return e("form",{staticClass:"custom-input__form",on:{"submit":function(t){t.preventDefault()}}},[e("input",{attrs:{"maxlength":"80","placeholder":this.$t("user_status","What's your status?"),"type":"text"},domProps:{"value":this.message},on:{"change":this.change}})])}),[],!1,null,"67479d68",null).exports),k=s(382),w={name:"ClearAtSelect",components:{Multiselect:s.n(k).a},props:{clearAt:{type:Object,default:null}},data:function(){return{options:[{label:Object(l.translate)("user_status","Don't clear"),clearAt:null},{label:Object(l.translate)("user_status","30 minutes"),clearAt:{type:"period",time:1800}},{label:Object(l.translate)("user_status","1 hour"),clearAt:{type:"period",time:3600}},{label:Object(l.translate)("user_status","4 hours"),clearAt:{type:"period",time:14400}},{label:Object(l.translate)("user_status","Today"),clearAt:{type:"end-of",time:"day"}},{label:Object(l.translate)("user_status","This week"),clearAt:{type:"end-of",time:"week"}}]}},computed:{option:function(){return{clearAt:this.clearAt,label:f(this.clearAt)}}},methods:{select:function(t){t&&this.$emit("selectClearAt",t.clearAt)}}},C=(s(393),Object(m.a)(w,(function(){var t=this.$createElement,e=this._self._c||t;return e("div",{staticClass:"clear-at-select"},[e("span",{staticClass:"clear-at-select__label"},[this._v("\n\t\t"+this._s(this.$t("user_status","Clear status message after"))+"\n\t")]),this._v(" "),e("Multiselect",{attrs:{"label":"label","value":this.option,"options":this.options,"open-direction":"top"},on:{"select":this.select}})],1)}),[],!1,null,"44cd4ace",null).exports),A={name:"OnlineStatusSelect",props:{checked:{type:Boolean,default:!1},icon:{type:String,required:!0},type:{type:String,required:!0}},computed:{id:function(){return"user-status-online-status-".concat(this.type)}},methods:{onChange:function(){this.$emit("select",this.type)}}},$=(s(395),Object(m.a)(A,(function(){var t=this.$createElement,e=this._self._c||t;return e("div",{staticClass:"user-status-online-select"},[e("input",{staticClass:"user-status-online-select__input",attrs:{"id":this.id,"type":"radio","name":"user-status-online"},domProps:{"checked":this.checked},on:{"change":this.onChange}}),this._v(" "),e("label",{staticClass:"user-status-online-select__label",class:this.icon,attrs:{"for":this.id}},[this._t("default")],2)])}),[],!1,null,"24baf5da",null).exports);function P(t,e,s,a,n,r,i){try{var u=t[r](i),l=u.value}catch(t){return void s(t)}u.done?e(l):Promise.resolve(l).then(a,n)}function M(t){return function(){var e=this,s=arguments;return new Promise((function(a,n){var r=t.apply(e,s);function i(t){P(r,a,n,i,u,"next",t)}function u(t){P(r,a,n,i,u,"throw",t)}i(void 0)}))}}var I={name:"SetStatusModal",components:{ClearAtSelect:C,CustomMessageInput:j,EmojiPicker:r.a,Modal:u.a,OnlineStatusSelect:$,PredefinedStatusesList:S},mixins:[o.a],data:function(){return{clearAt:null,icon:null,message:null,statuses:[{type:"online",label:Object(l.translate)("user_status","Online"),icon:"icon-user-status-online"},{type:"away",label:Object(l.translate)("user_status","Away"),icon:"icon-user-status-away"},{type:"dnd",label:Object(l.translate)("user_status","Do not disturb"),subline:Object(l.translate)("user_status","Mute all notifications"),icon:"icon-user-status-dnd"},{type:"invisible",label:Object(l.translate)("user_status","Invisible"),subline:Object(l.translate)("user_status","Appear offline"),icon:"icon-user-status-invisible"}]}},computed:{visibleIcon:function(){return this.icon||"😀"}},mounted:function(){this.messageId=this.$store.state.userStatus.messageId,this.icon=this.$store.state.userStatus.icon,this.message=this.$store.state.userStatus.message,null!==this.$store.state.userStatus.clearAt&&(this.clearAt={type:"_time",time:this.$store.state.userStatus.clearAt})},methods:{closeModal:function(){this.$emit("close")},setIcon:function(t){this.messageId=null,this.icon=t},setMessage:function(t){this.messageId=null,this.message=t},setClearAt:function(t){this.clearAt=t},selectPredefinedMessage:function(t){this.messageId=t.id,this.clearAt=t.clearAt,this.icon=t.icon,this.message=t.message},saveStatus:function(){var t=this;return M(regeneratorRuntime.mark((function e(){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(e.prev=0,t.isSavingStatus=!0,null===t.messageId){e.next=7;break}return e.next=5,t.$store.dispatch("setPredefinedMessage",{messageId:t.messageId,clearAt:t.clearAt});case 5:e.next=9;break;case 7:return e.next=9,t.$store.dispatch("setCustomMessage",{message:t.message,icon:t.icon,clearAt:t.clearAt});case 9:e.next=17;break;case 11:return e.prev=11,e.t0=e.catch(0),Object(a.a)(t.$t("user_status","There was an error saving the status")),console.debug(e.t0),t.isSavingStatus=!1,e.abrupt("return");case 17:t.isSavingStatus=!1,t.closeModal();case 19:case"end":return e.stop()}}),e,null,[[0,11]])})))()},clearStatus:function(){var t=this;return M(regeneratorRuntime.mark((function e(){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,t.isSavingStatus=!0,e.next=4,t.$store.dispatch("clearMessage");case 4:e.next=12;break;case 6:return e.prev=6,e.t0=e.catch(0),Object(a.a)(t.$t("user_status","There was an error clearing the status")),console.debug(e.t0),t.isSavingStatus=!1,e.abrupt("return");case 12:t.isSavingStatus=!1,t.closeModal();case 14:case"end":return e.stop()}}),e,null,[[0,6]])})))()}}},E=(s(397),Object(m.a)(I,(function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("Modal",{attrs:{"size":"normal","title":t.$t("user_status","Set status")},on:{"close":t.closeModal}},[s("div",{staticClass:"set-status-modal"},[s("div",{staticClass:"set-status-modal__header"},[s("h3",[t._v(t._s(t.$t("user_status","Online status")))])]),t._v(" "),s("div",{staticClass:"set-status-modal__online-status"},t._l(t.statuses,(function(e){return s("OnlineStatusSelect",t._b({key:e.type,attrs:{"checked":e.type===t.statusType},on:{"select":t.changeStatus}},"OnlineStatusSelect",e,!1),[t._v("\n\t\t\t\t"+t._s(e.label)+"\n\t\t\t\t"),s("em",{staticClass:"subline"},[t._v(t._s(e.subline))])])})),1),t._v(" "),s("div",{staticClass:"set-status-modal__header"},[s("h3",[t._v(t._s(t.$t("user_status","Status message")))])]),t._v(" "),s("div",{staticClass:"set-status-modal__custom-input"},[s("EmojiPicker",{on:{"select":t.setIcon}},[s("button",{staticClass:"custom-input__emoji-button"},[t._v("\n\t\t\t\t\t"+t._s(t.visibleIcon)+"\n\t\t\t\t")])]),t._v(" "),s("CustomMessageInput",{attrs:{"message":t.message},on:{"change":t.setMessage}})],1),t._v(" "),s("PredefinedStatusesList",{on:{"selectStatus":t.selectPredefinedMessage}}),t._v(" "),s("ClearAtSelect",{attrs:{"clear-at":t.clearAt},on:{"selectClearAt":t.setClearAt}}),t._v(" "),s("div",{staticClass:"status-buttons"},[s("button",{staticClass:"status-buttons__select",on:{"click":t.clearStatus}},[t._v("\n\t\t\t\t"+t._s(t.$t("user_status","Clear status message"))+"\n\t\t\t")]),t._v(" "),s("button",{staticClass:"status-buttons__primary primary",on:{"click":t.saveStatus}},[t._v("\n\t\t\t\t"+t._s(t.$t("user_status","Set status message"))+"\n\t\t\t")])])],1)])}),[],!1,null,"710897d4",null));e.default=E.exports}}]);
//# sourceMappingURL=user-status-modal.js.map?v=d75f07a9dac276a95526