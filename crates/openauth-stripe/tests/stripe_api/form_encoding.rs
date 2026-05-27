use openauth_stripe::stripe_api::encode_form;
use serde_json::json;

#[test]
fn form_encoder_uses_stripe_bracket_notation() {
    let encoded = encode_form(&json!({
        "customer": "cus_123",
        "line_items": [
            { "price": "price_base", "quantity": 1 },
            { "price": "price_metered" }
        ],
        "subscription_data": {
            "metadata": {
                "subscriptionId": "sub_local"
            }
        }
    }));

    assert!(encoded.contains("customer=cus_123"));
    assert!(encoded.contains("line_items%5B0%5D%5Bprice%5D=price_base"));
    assert!(encoded.contains("line_items%5B0%5D%5Bquantity%5D=1"));
    assert!(encoded.contains("line_items%5B1%5D%5Bprice%5D=price_metered"));
    assert!(encoded.contains("subscription_data%5Bmetadata%5D%5BsubscriptionId%5D=sub_local"));
}

#[test]
fn form_encoder_handles_schedule_phases_empty_strings_and_null_omission() {
    let encoded = encode_form(&json!({
        "cancel_at": "",
        "metadata": {
            "source": "@better-auth/stripe",
            "ignored": null
        },
        "phases": [
            {
                "items": [
                    { "price": "price_current", "quantity": 1 }
                ],
                "start_date": 1,
                "end_date": 2
            },
            {
                "items": [
                    { "price": "price_next" }
                ],
                "proration_behavior": "none"
            }
        ]
    }));

    assert!(encoded.contains("cancel_at="));
    assert!(encoded.contains("metadata%5Bsource%5D=%40better-auth%2Fstripe"));
    assert!(!encoded.contains("ignored"));
    assert!(encoded.contains("phases%5B0%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_current"));
    assert!(encoded.contains("phases%5B1%5D%5Bitems%5D%5B0%5D%5Bprice%5D=price_next"));
    assert!(encoded.contains("phases%5B1%5D%5Bproration_behavior%5D=none"));
}
