package models

import (
	"encoding/json"
	"errors"
	"html"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

type Sales struct {
	ID               uint32          `gorm:"primary_key;auto_increment" json:"id"`
	Create_dtm       time.Time       `json:"create_dtm"`
	Sales_id         string          `json:"sales_id"`
	User_id          string          `json:"user_id"`
	Outlet_id        string          `json:"outlet_id"`
	Sales_type       string          `json:"sales_type"`
	Customer_id      string          `json:"customer_id"`
	Products         json.RawMessage `json:"products"`
	Subtotal         int             `json:"subtotal"`
	Total_diskon     int             `json:"total_diskon"`
	Total_tax        json.RawMessage `json:"total_tax"`
	Total_bill       int             `json:"total_bill"`
	Payment_method   string          `json:"payment_method"`
	Payment_due_date string          `json:"payment_due_date"`
	Total_payment    int             `json:"total_payment"`
	Exchange         int             `json:"exchange"`
	Notes            string          `json:"notes"`
	Total_buy_cost   int             `json:"total_buy_cost"`
	Payment_date     string          `json:"payment_date"`
	Reward_id        string          `json:"Reward_id"`
	Points_redeem    int             `json:"points_redeem"`
}
type Data struct {
	UserID    string
	OwnerName string
	Email     string
	LastTrx   time.Time
}

func (w *Sales) Prepare() {
	w.Sales_type = html.EscapeString(strings.TrimSpace(w.Sales_type))
	w.Create_dtm = time.Now()
}

func (w *Sales) Validate() map[string]string {

	var err error

	var errorMessages = make(map[string]string)

	if w.Customer_id == "" {
		err = errors.New("Required Customer")
		errorMessages["Required_Customer"] = err.Error()
	}
	if w.Outlet_id == "" {
		err = errors.New("Required Outlet")
		errorMessages["Required_Outlet"] = err.Error()
	}
	return errorMessages
}

func (w *Sales) SaveSales(db *gorm.DB) (*Sales, error) {
	var err error
	err = db.Debug().Model(&Sales{}).Create(&w).Error
	if err != nil {
		return &Sales{}, err
	}
	if w.User_id == "" {
		err = db.Debug().Model(&Sales{}).Where("user_id = ?", w.User_id).Error
		if err != nil {
			return &Sales{}, err
		}
	}
	return w, nil
}

func (w *Sales) FindSales(db *gorm.DB) (*Sales, error) {
	var err error
	err = db.Debug().Model(Sales{}).Where("created_at > ?", time.Now().Add(-168*time.Hour)).Take(&w).Error
	if err != nil {
		return &Sales{}, err
	}
	if gorm.IsRecordNotFoundError(err) {
		return &Sales{}, errors.New("User Not Found")
	}
	return w, err
}

// func Show(db *gorm.DB) (error, []Data) {
// 	var datas []Data

// 	rows, err := db.Raw(`SELECT user_id, owner_name, email, Z.create_dtm as last_trx FROM (
// 		SELECT user_id,owner_name, email, (SELECT create_dtm FROM sales WHERE create_dtm > current_date-7 AND user_id = b.user_id ORDER BY id DESC LIMIT 1) FROM subscribers b
// 		UNION SELECT user_id, owner_name, email, (SELECT create_dtm FROM onlinesales WHERE create_dtm > current_date-7 AND user_id = b.user_id ORDER BY id DESC LIMIT 1) FROM subscribers b
// 		UNION SELECT user_id, owner_name, email, (SELECT create_dtm FROM saved_orders so WHERE create_dtm > current_date-7 AND user_id = b.user_id ORDER BY id DESC LIMIT 1) FROM subscribers b) AS Z`).Rows()

// 	if err != nil {
// 		fmt.Errorf("%v", err)
// 		return err, datas
// 	}

// 	defer rows.Close()

// 	for rows.Next() {
// 		var (
// 			user_id    sql.NullString
// 			owner_name sql.NullString
// 			email      sql.NullString
// 			last_trx   sql.NullTime
// 		)

// 		err = rows.Scan(&user_id, &owner_name, &email, &last_trx)
// 		if err != nil {
// 			// handle this error
// 			fmt.Errorf("%v", err)
// 			return err, datas
// 		}

// 		datas = append(datas, Data{
// 			UserID:    user_id.String,
// 			OwnerName: owner_name.String,
// 			Email:     email.String,
// 			LastTrx:   last_trx.Time,
// 		})
// 	}

// 	return nil, datas
// }
