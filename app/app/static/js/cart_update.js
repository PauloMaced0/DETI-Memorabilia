$(document).ready(function () {
    let qty_btns = document.getElementsByClassName('quantity_update');
    let final_total = document.getElementById("final_total");
    Array.from(qty_btns).forEach(btn => {
        const item_id = btn.getAttribute('data-id');
        if(btn.classList.contains(`subtract${item_id}`) && parseInt(document.getElementById(item_id).textContent) == 1) 
            btn.setAttribute('disabled', '');
        $(btn).click(function (e) { 
                e.preventDefault();
                let element_quantity = document.getElementById(item_id);
                const value = btn.getAttribute('value');
                const quantity = parseInt(element_quantity.textContent) + parseInt(value);
                $.ajax({
                    type: "PUT",
                    url: "/cart/update_item",
                    data: {
                        value: quantity, 
                        cart_id: item_id},
                        dataType: "json",
                    success: function (response) {
                    let element_totalPrice = document.getElementsByClassName(`total_price${item_id}`)[0]
                    const old_totalPrice = parseFloat(element_totalPrice.textContent.substring(1));
                    const price = old_totalPrice / parseFloat(element_quantity.textContent);
                    element_quantity.textContent = quantity;
                    const newTotalPrice = price * quantity;
                    element_totalPrice.textContent = '$'+newTotalPrice.toFixed(2);
                    if(quantity == 1 && value==-1) btn.setAttribute('disabled', '')
                    else{
                        const sub_btn = document.getElementsByClassName(`subtract${item_id}`)
                        sub_btn[0].removeAttribute('disabled')
                    }
                    lastFinalTotalPrice = parseFloat(final_total.textContent.substring(8))
                    final_total.textContent = 'Total: $'+(lastFinalTotalPrice+newTotalPrice-old_totalPrice).toFixed(2);
                }
            });
        });
    });
});
