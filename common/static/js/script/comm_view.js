/**
 * Created by kotech on 2018. 2. 6..
 */

$(document).ready(function(){

    var file_check = $("ul #file_li").length;
    if(file_check != 0){
        $("#file_li p a").click(function () {
            var down_link = this;
            var down_path = this.pathname;

            console.log(down_path);
            $(this).css({'pointer-events': 'none'});
            setTimeout(function () {
                $(down_link).attr('href', down_path);
                $(down_link).css({'pointer-events': 'auto'});
            }, 5000);
        });
    }
});
